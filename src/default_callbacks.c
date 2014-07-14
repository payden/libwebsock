/*
 * This file is part of libwebsock
 *
 * Copyright (C) 2012-2013 Payden Sutherland
 *
 * libwebsock is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * libwebsock is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwebsock; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "websock.h"

int
libwebsock_default_onclose_callback(libwebsock_client_state *state)
{
  fprintf(stderr, "Closing connection with socket descriptor: %d\n", state->sockfd);
  return 0;
}

int
libwebsock_default_onopen_callback(libwebsock_client_state *state)
{
  fprintf(stderr, "New connection with socket descriptor: %d\n", state->sockfd);
  return 0;
}

int
libwebsock_default_onmessage_callback(libwebsock_client_state *state, libwebsock_message *msg)
{
  libwebsock_send_text(state, msg->payload);
  return 0;
}

int
libwebsock_default_control_callback(libwebsock_client_state *state, libwebsock_frame *ctl_frame)
{
  struct evbuffer *output = bufferevent_get_output(state->bev);
  int i;
  unsigned short code;
  unsigned short code_be;

  if ((state->flags & STATE_SENT_CLOSE_FRAME) && (ctl_frame->opcode != WS_OPCODE_CLOSE)) {
    return 0;
  }
  if (ctl_frame->payload_len > 125) {
    libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
    if (ctl_frame->opcode == WS_OPCODE_CLOSE) {
      libwebsock_shutdown(state);
    }
    return 0;
  }

  //servify frame
  for (i = 0; i < ctl_frame->payload_len; i++) {
    //this demasks the payload while shifting it 4 bytes to the left.
    *(ctl_frame->rawdata + ctl_frame->payload_offset + i - 4) =
        *(ctl_frame->rawdata + ctl_frame->payload_offset + i) ^ (ctl_frame->mask[i % 4] & 0xff);
  }
  ctl_frame->payload_offset -= 4;
  *(ctl_frame->rawdata + 1) &= 0x7f; //strip mask bit
  switch (ctl_frame->opcode) {
    case WS_OPCODE_CLOSE:  //close frame
      if (!state->close_info && ctl_frame->payload_len >= 2) {
        libwebsock_populate_close_info_from_frame(&state->close_info, ctl_frame);
      }
      if (ctl_frame->payload_len > 0 && ctl_frame->payload_len < 2) {
        libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
        libwebsock_shutdown(state);
        return 0;
      }
      if (state->close_info) {
        code = state->close_info->code;
        if ((code >= 0 && code < WS_CLOSE_NORMAL) || code == WS_CLOSE_RESERVED || code == WS_CLOSE_NO_CODE
            || code == WS_CLOSE_DIRTY || (code > 1011 && code < 3000)) {

          code_be = htobe16(WS_CLOSE_PROTOCOL_ERROR);
          memcpy(ctl_frame->rawdata + ctl_frame->payload_offset, &code_be, 2);
        } else if (!validate_utf8_sequence((uint8_t *)state->close_info->reason)) {
          code_be = htobe16(WS_CLOSE_WRONG_TYPE);
          memcpy(ctl_frame->rawdata + ctl_frame->payload_offset, &code_be, 2);
        }
      }
      if ((state->flags & STATE_SENT_CLOSE_FRAME) == 0){
        //client request close.  Echo close frame as acknowledgement
        state->flags |= STATE_SHOULD_CLOSE|STATE_SENT_CLOSE_FRAME|STATE_RECEIVED_CLOSE_FRAME;
        evbuffer_add(output, ctl_frame->rawdata, ctl_frame->payload_offset + ctl_frame->payload_len);
        if (state->flags & STATE_IS_SSL) {
          libwebsock_shutdown(state);
        } else {
          bufferevent_setcb(state->bev, NULL, libwebsock_shutdown_after_send, NULL, (void *) state);
        }
        return 0;
      } else {
        if ((state->flags & STATE_RECEIVED_CLOSE_FRAME) == 0) { //received first close frame and already sent.
          state->flags |= STATE_RECEIVED_CLOSE_FRAME;
          libwebsock_shutdown(state);
        } else {
          //received second close frame?
          return 0;
        }
      }
      break;
    case WS_OPCODE_PING:
      *(ctl_frame->rawdata) = 0x8a;
      evbuffer_add(output, ctl_frame->rawdata, ctl_frame->payload_offset + ctl_frame->payload_len);
      break;
    case WS_OPCODE_PONG:
      if (state->onpong != NULL) {
        state->onpong(state);
      }
      break;
    default:
      libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
      break;
  }
  return 1;
}
