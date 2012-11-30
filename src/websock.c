/*
 * This file is part of libwebsock
 *
 * Copyright (C) 2012 Payden Sutherland
 *
 * libwebsock is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * libwebsock is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libwebsock; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "websock.h"
#include "sha1.h"
#include "base64.h"


void
libwebsock_handle_signal(evutil_socket_t sig, short event, void *ptr)
{
  libwebsock_context *ctx = ptr;
  event_base_loopexit(ctx->base, NULL);
}

void
libwebsock_populate_close_info_from_frame(libwebsock_close_info **info, libwebsock_frame *close_frame)
{
  libwebsock_close_info *new_info;
  unsigned short code_be;
  int at_most;

  if (close_frame->payload_len < 2) {
    return;
  }

  new_info = (libwebsock_close_info *) malloc(sizeof(libwebsock_close_info));
  if (!new_info) {
    fprintf(stderr, "Error allocating memory for libwebsock_close_info structure.\n");
    return;
  }

  memset(new_info, 0, sizeof(libwebsock_close_info));
  memcpy(&code_be, close_frame->rawdata + close_frame->payload_offset, 2);
  at_most = close_frame->payload_len - 2;
  at_most = at_most > 124 ? 124 : at_most;
  new_info->code = be16toh(code_be);
  if (close_frame->payload_len - 2 > 0) {
    memcpy(new_info->reason, close_frame->rawdata + close_frame->payload_offset + 2, at_most);
  }
  *info = new_info;
}

void
libwebsock_shutdown(libwebsock_client_state *state)
{
  libwebsock_string *str;
  if ((state->flags & STATE_CONNECTED) && state->onclose) {
    state->onclose(state);
  }
  if (state->close_info) {
    free(state->close_info);
  }
  libwebsock_free_all_frames(state);
  if (state->sa) {
    free(state->sa);
  }
  if (state->flags & STATE_CONNECTING) {
    if (state->data) {
      str = state->data;
      if (str->data) {
        free(str->data);
      }
      free(str);
    }
  }

  bufferevent_free(state->bev);
  free(state);
}

void
libwebsock_handle_send(struct bufferevent *bev, void *arg)
{
  libwebsock_client_state *state = arg;

  if (state->flags & STATE_SHOULD_CLOSE) {
    libwebsock_shutdown(state);
  }

}

void
libwebsock_send_cleanup(const void *data, size_t len, void *arg)
{
  free((void *) data);
}

int
libwebsock_send_fragment(libwebsock_client_state *state, const char *data, unsigned long long len, int flags)
{
  struct evbuffer *output = bufferevent_get_output(state->bev);
  unsigned long long payload_len_long_be;
  unsigned short int payload_len_short_be;
  unsigned char finNopcode, payload_len_small;
  unsigned int payload_offset = 2;
  unsigned int frame_size;
  char *frame;

  finNopcode = flags & 0xff;
  if (len <= 125) {
    frame_size = 2 + len;
    payload_len_small = len & 0xff;
  } else if (len > 125 && len <= 0xffff) {
    frame_size = 4 + len;
    payload_len_small = 126;
    payload_offset += 2;
  } else if (len > 0xffff && len <= 0xffffffffffffffffLL) {
    frame_size = 10 + len;
    payload_len_small = 127;
    payload_offset += 8;
  } else {
    fprintf(stderr, "Whoa man.  What are you trying to send?\n");
    return -1;
  }
  frame = (char *) malloc(frame_size);
  memset(frame, 0, frame_size);
  payload_len_small &= 0x7f;
  *frame = finNopcode;
  *(frame + 1) = payload_len_small;
  if (payload_len_small == 126) {
    len &= 0xffff;
    payload_len_short_be = htobe16(len);
    memcpy(frame + 2, &payload_len_short_be, 2);
  }
  if (payload_len_small == 127) {
    payload_len_long_be = htobe64(len);
    memcpy(frame + 2, &payload_len_long_be, 8);
  }
  memcpy(frame + payload_offset, data, len);

  return evbuffer_add_reference(output, frame, frame_size, libwebsock_send_cleanup, NULL);
}

void
libwebsock_handle_accept(evutil_socket_t listener, short event, void *arg)
{
  libwebsock_context *ctx = arg;
  libwebsock_client_state *client_state;
  struct bufferevent *bev;
  struct sockaddr_storage ss;
  socklen_t slen = sizeof(ss);
  int fd = accept(listener, (struct sockaddr *) &ss, &slen);
  if (fd < 0) {
    fprintf(stderr, "Error accepting new connection.\n");
  } else {
    client_state = (libwebsock_client_state *) malloc(sizeof(libwebsock_client_state));
    if (!client_state) {
      fprintf(stderr, "Unable to allocate memory for new connection state structure.\n");
      close(fd);
      return;
    }
    memset(client_state, 0, sizeof(libwebsock_client_state));
    client_state->sockfd = fd;
    client_state->flags |= STATE_CONNECTING;
    client_state->control_callback = ctx->control_callback;
    client_state->onopen = ctx->onopen;
    client_state->onmessage = ctx->onmessage;
    client_state->onclose = ctx->onclose;
    client_state->sa = (struct sockaddr_storage *) malloc(sizeof(struct sockaddr_storage));
    if (!client_state->sa) {
      fprintf(stderr, "Unable to allocate memory for sockaddr_storage.\n");
      free(client_state);
      close(fd);
      return;
    }
    memcpy(client_state->sa, &ss, sizeof(struct sockaddr_storage));
    evutil_make_socket_nonblocking(fd);
    bev = bufferevent_socket_new(ctx->base, fd, BEV_OPT_CLOSE_ON_FREE);
    client_state->bev = bev;
    bufferevent_setcb(bev, libwebsock_handshake, libwebsock_handle_send, libwebsock_do_event, (void *) client_state);
    bufferevent_setwatermark(bev, EV_READ, 0, 16384);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
  }
}

void
libwebsock_do_event(struct bufferevent *bev, short event, void *ptr)
{
  libwebsock_client_state *state = ptr;

  if (event & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
    libwebsock_shutdown(state);
  }
}

void
libwebsock_handle_recv(struct bufferevent *bev, void *ptr)
{
  //alright... while we haven't reached the end of data keep trying to build frames
  //possible states right now:
  // 1.) we're receiving the beginning of a new frame
  // 2.) we're receiving more data from a frame that was created previously and was not complete
  libwebsock_client_state *state = ptr;
  libwebsock_frame *current = NULL, *new = NULL;
  struct evbuffer *input;
  int i, datalen, err;
  char buf[1024];

  input = bufferevent_get_input(bev);
  while (evbuffer_get_length(input)) {
    datalen = evbuffer_remove(input, buf, sizeof(buf));
    for (i = 0; i < datalen; i++) {
      if (state->current_frame == NULL) {
        state->current_frame = (libwebsock_frame *) malloc(sizeof(libwebsock_frame));
        memset(state->current_frame, 0, sizeof(libwebsock_frame));
        state->current_frame->payload_len = -1;
        state->current_frame->rawdata_sz = FRAME_CHUNK_LENGTH;
        state->current_frame->rawdata = (char *) malloc(state->current_frame->rawdata_sz);
      }
      current = state->current_frame;
      if (current->rawdata_idx >= current->rawdata_sz) {
        current->rawdata_sz += current->rawdata_sz;
        current->rawdata = (char *) realloc(current->rawdata, current->rawdata_sz);
      }
      *(current->rawdata + current->rawdata_idx++) = buf[i];
      if (current->state != sw_loaded_mask) {
        err = libwebsock_read_header(current);
        if (err == -1) {
          libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
        }
        if (err == 0) {
          continue;
        }
      }

      if (current->rawdata_idx < current->payload_offset + current->payload_len) {
        continue;
      }

      if (state->flags & STATE_RECEIVING_FRAGMENT) {
        if (current->fin == 1) {
          if ((current->opcode & 0x8) == 0) {
            if (current->opcode) { //non-ctrl and has opcode in the middle of fragment.  FAIL
              libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
              break;
            }
            state->flags &= ~STATE_RECEIVING_FRAGMENT;
          }
          libwebsock_frame_act(state, current);
        } else {
          //middle of fragment non-fin frame
          if (current->opcode) { //cannot have opcode
            libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
            break;
          }
          new = (libwebsock_frame *) malloc(sizeof(libwebsock_frame));
          memset(new, 0, sizeof(libwebsock_frame));
          new->rawdata_sz = FRAME_CHUNK_LENGTH;
          new->rawdata = (char *) malloc(new->rawdata_sz);
          new->prev_frame = current;
          current->next_frame = new;
          state->current_frame = new;
        }
      } else {
        if (current->fin == 1) {
          //first frame and FIN, handle normally.
          if (!current->opcode) { //must have opcode, cannot be continuation frame.
            libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
            break;
          }
          libwebsock_frame_act(state, current);
        } else {
          //new fragment series beginning
          if (current->opcode & 0x8) { //can't fragment control frames.  FAIL
            libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
            break;
          }
          if (!current->opcode) { //new fragment series must have opcode.
            libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
            break;
          }
          new = (libwebsock_frame *) malloc(sizeof(libwebsock_frame));
          memset(new, 0, sizeof(libwebsock_frame));
          new->rawdata_sz = FRAME_CHUNK_LENGTH;
          new->rawdata = (char *) malloc(new->rawdata_sz);
          new->prev_frame = current;
          current->next_frame = new;
          state->current_frame = new;
          state->flags |= STATE_RECEIVING_FRAGMENT;
        }
      }
      if (state->flags & STATE_SHOULD_CLOSE) { //after each complete frame, check to see if we should stop processing now.
        break;
      }
    }
  }
}

void
libwebsock_fail_connection(libwebsock_client_state *state, unsigned short close_code)
{
  struct evbuffer *output = bufferevent_get_output(state->bev);
  char close_frame[4] = { 0x88, 0x02, 0x00, 0x00 };
  unsigned short code_be = htobe16(close_code);
  memcpy(&close_frame[2], &code_be, 2);

  evbuffer_add(output, close_frame, 4);
  state->flags |= STATE_SHOULD_CLOSE;
}

void
libwebsock_dispatch_message(libwebsock_client_state *state, libwebsock_frame *current)
{
  unsigned long long message_payload_len, message_offset;
  int message_opcode, i;
  char *message_payload;

  libwebsock_frame *first = NULL;
  libwebsock_message *msg = NULL;
  if (current == NULL) {
    fprintf(stderr, "Somehow, null pointer passed to libwebsock_dispatch_message.\n");
    exit(1);
  }
  message_offset = 0;
  message_payload_len = 0;
  for (; current->prev_frame != NULL; current = current->prev_frame) {
    message_payload_len += current->payload_len;
  }
  message_payload_len += current->payload_len;
  first = current;
  message_opcode = current->opcode;
  message_payload = (char *) malloc(message_payload_len + 1);

  for (; current != NULL; current = current->next_frame) {
    for (i = 0; i < current->payload_len; i++) {
      *(message_payload + message_offset++) =
          *(current->rawdata + current->payload_offset + i) ^ (current->mask[i % 4] & 0xff);
    }
  }

  *(message_payload + message_offset) = '\0';

  libwebsock_cleanup_frames(first);

  if(message_opcode == WS_OPCODE_TEXT) {
    if(!validate_utf8_sequence((uint8_t *)message_payload)) {
      fprintf(stderr, "Error validating UTF-8 sequence.\n");
      free(message_payload);
      libwebsock_fail_connection(state, WS_CLOSE_WRONG_TYPE);
      return;
    }
  }

  msg = (libwebsock_message *) malloc(sizeof(libwebsock_message));
  memset(msg, 0, sizeof(libwebsock_message));
  msg->opcode = message_opcode;
  msg->payload_len = message_payload_len;
  msg->payload = message_payload;
  if (state->onmessage != NULL) {
    state->onmessage(state, msg);
  } else {
    fprintf(stderr, "No onmessage call back registered with libwebsock.\n");
  }
  free(msg->payload);
  free(msg);
}

void
libwebsock_handshake_finish(struct bufferevent *bev, libwebsock_client_state *state)
{
  //TODO: this is shite.  Clean it up.
  libwebsock_string *str = state->data;
  struct evbuffer *output;
  char buf[1024];
  char sha1buf[45];
  char concat[1024];
  unsigned char sha1mac[20];
  char *tok = NULL, *headers = NULL, *key = NULL;
  char *base64buf = NULL;
  const char *GID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  SHA1Context shactx;
  SHA1Reset(&shactx);
  int n = 0;

  output = bufferevent_get_output(bev);

  headers = (char *) malloc(str->data_sz + 1);
  if (!headers) {
    fprintf(stderr, "Unable to allocate memory in libwebsock_handshake..\n");
    bufferevent_free(bev);
    return;
  }
  memset(headers, 0, str->data_sz + 1);
  strncpy(headers, str->data, str->idx);
  for (tok = strtok(headers, "\r\n"); tok != NULL; tok = strtok(NULL, "\r\n")) {
    if (strstr(tok, "Sec-WebSocket-Key: ") != NULL) {
      key = (char *) malloc(strlen(tok));
      strncpy(key, tok + strlen("Sec-WebSocket-Key: "), strlen(tok));
      break;
    }
  }
  free(headers);
  free(str->data);
  free(str);
  state->data = NULL;

  if (key == NULL) {
    fprintf(stderr, "Unable to find key in request headers.\n");
    bufferevent_free(bev);
    return;
  }

  memset(concat, 0, sizeof(concat));
  strncat(concat, key, strlen(key));
  strncat(concat, GID, strlen(GID));
  SHA1Input(&shactx, (unsigned char *) concat, strlen(concat));
  SHA1Result(&shactx);
  free(key);
  key = NULL;
  sprintf(sha1buf, "%08x%08x%08x%08x%08x", shactx.Message_Digest[0], shactx.Message_Digest[1], shactx.Message_Digest[2],
      shactx.Message_Digest[3], shactx.Message_Digest[4]);
  for (n = 0; n < (strlen(sha1buf) / 2); n++) {
    sscanf(sha1buf + (n * 2), "%02hhx", sha1mac + n);
  }
  base64buf = (char *) malloc(256);
  base64_encode(sha1mac, 20, base64buf, 256);
  memset(buf, 0, 1024);
  snprintf(buf, 1024,
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Server: %s/%s\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: %s\r\n\r\n", PACKAGE_NAME, PACKAGE_VERSION, base64buf);
  free(base64buf);

  evbuffer_add(output, buf, strlen(buf));
  bufferevent_setcb(bev, libwebsock_handle_recv, libwebsock_handle_send, libwebsock_do_event, (void *) state);

  state->flags &= ~STATE_CONNECTING;
  state->flags |= STATE_CONNECTED;

  if (state->onopen != NULL) {
    state->onopen(state);
  }
}

void
libwebsock_handshake(struct bufferevent *bev, void *ptr)
{
  //TODO: this is shite too.
  libwebsock_client_state *state = ptr;
  libwebsock_string *str = NULL;
  struct evbuffer *input;
  char buf[1024];
  int datalen;
  input = bufferevent_get_input(bev);
  str = state->data;
  if (!str) {
    state->data = (libwebsock_string *) malloc(sizeof(libwebsock_string));
    if (!state->data) {
      fprintf(stderr, "Unable to allocate memory in libwebsock_handshake.\n");
      bufferevent_free(bev);
      return;
    }
    str = state->data;
    memset(str, 0, sizeof(libwebsock_string));
    str->data_sz = FRAME_CHUNK_LENGTH;
    str->data = (char *) malloc(str->data_sz);
    if (!str->data) {
      fprintf(stderr, "Unable to allocate memory in libwebsock_handshake.\n");
      bufferevent_free(bev);
      return;
    }
    memset(str->data, 0, str->data_sz);
  }

  while (evbuffer_get_length(input)) {
    datalen = evbuffer_remove(input, buf, sizeof(buf));

    if (str->idx + datalen >= str->data_sz) {
      str->data = realloc(str->data, str->data_sz * 2 + datalen);
      if (!str->data) {
        fprintf(stderr, "Failed realloc.\n");
        bufferevent_free(bev);
        return;
      }
      str->data_sz += str->data_sz + datalen;
      memset(str->data + str->idx, 0, str->data_sz - str->idx);
    }
    memcpy(str->data + str->idx, buf, datalen);
    str->idx += datalen;
    if (strstr(str->data, "\r\n\r\n") != NULL || strstr(str->data, "\n\n") != NULL) {
      libwebsock_handshake_finish(bev, state);
    }
  }
}


