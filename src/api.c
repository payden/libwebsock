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
#include <signal.h>
#include <unistd.h>

#ifndef _WIN32
#include <netdb.h>
#endif

#include "websock.h"



void
libwebsock_dump_frame(libwebsock_frame *frame)
{
  int i;
  fprintf(stderr, "FIN: %d\n", frame->fin);
  fprintf(stderr, "Opcode: %d\n", frame->opcode);
  fprintf(stderr, "mask_offset: %d\n", frame->mask_offset);
  fprintf(stderr, "payload_offset: %d\n", frame->payload_offset);
  fprintf(stderr, "rawdata_idx: %d\n", frame->rawdata_idx);
  fprintf(stderr, "rawdata_sz: %d\n", frame->rawdata_sz);
  fprintf(stderr, "payload_len: %llu\n", frame->payload_len);
  fprintf(stderr, "Has previous frame: %d\n", frame->prev_frame != NULL ? 1 : 0);
  fprintf(stderr, "Has next frame: %d\n", frame->next_frame != NULL ? 1 : 0);
  fprintf(stderr, "Raw data:\n");
  fprintf(stderr, "%02x", *(frame->rawdata) & 0xff);
  for (i = 1; i < frame->rawdata_idx; i++) {
    fprintf(stderr, ":%02x", *(frame->rawdata + i) & 0xff);
  }
  fprintf(stderr, "\n");
}

int
libwebsock_close(libwebsock_client_state *state)
{
  return libwebsock_close_with_reason(state, WS_CLOSE_NORMAL, NULL );
}

int
libwebsock_close_with_reason(libwebsock_client_state *state, unsigned short code, const char *reason)
{
  unsigned long long len;
  unsigned short code_be;
  int ret;
  char buf[128]; //w3 spec on WebSockets API (http://dev.w3.org/html5/websockets/) says reason shouldn't be over 123 bytes.  I concur.
  len = 2;
  code_be = htobe16(code);
  memcpy(buf, &code_be, 2);
  if (reason) {
    len += snprintf(buf + 2, 124, "%s", reason);
  }
  int flags = WS_FRAGMENT_FIN | WS_OPCODE_CLOSE;
  ret = libwebsock_send_fragment(state, buf, len, flags);
  state->flags |= STATE_SENT_CLOSE_FRAME;
  return ret;
}

int
libwebsock_send_text_with_length(libwebsock_client_state *state, char *strdata, unsigned long long payload_len)
{
  int flags = WS_FRAGMENT_FIN | WS_OPCODE_TEXT;
  return libwebsock_send_fragment(state, strdata, payload_len, flags);
}

int
libwebsock_send_text(libwebsock_client_state *state, char *strdata)
{
  unsigned long long len = strlen(strdata);
  int flags = WS_FRAGMENT_FIN | WS_OPCODE_TEXT;
  return libwebsock_send_fragment(state, strdata, len, flags);
}

int
libwebsock_send_binary(libwebsock_client_state *state, char *in_data, unsigned long long payload_len)
{
  int flags = WS_FRAGMENT_FIN | WS_OPCODE_BINARY;
  return libwebsock_send_fragment(state, in_data, payload_len, flags);
}

void
libwebsock_wait(libwebsock_context *ctx)
{
  struct event *sig_event;
  sig_event = evsignal_new(ctx->base, SIGINT, libwebsock_handle_signal, (void *)ctx);
  event_add(sig_event, NULL );
  ctx->running = 1;
  event_base_dispatch(ctx->base);
  ctx->running = 0;
  event_free(sig_event);
}

void
libwebsock_bind(libwebsock_context *ctx, char *listen_host, char *port)
{
  struct addrinfo hints, *servinfo, *p;
  struct event *listener_event;

  evutil_socket_t sockfd;
  int yes = 1;
  memset(&hints, 0, sizeof(struct addrinfo));

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  if ((getaddrinfo(listen_host, port, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo failed during libwebsock_bind.\n");
    free(ctx);
    exit(-1);
  }
  for (p = servinfo; p != NULL ; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("socket");
      continue;
    }

    evutil_make_socket_nonblocking(sockfd);

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      perror("setsockopt");
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      perror("bind");
      close(sockfd);
      continue;
    }
    break;
  }

  if (p == NULL) {
    fprintf(stderr, "Failed to bind to address and port.  Exiting.\n");
    free(ctx);
    exit(-1);
  }

  freeaddrinfo(servinfo);

  if (listen(sockfd, LISTEN_BACKLOG) == -1) {
    perror("listen");
    exit(-1);
  }

  listener_event = event_new(ctx->base, sockfd, EV_READ | EV_PERSIST, libwebsock_handle_accept, (void *) ctx);
  event_add(listener_event, NULL );
}

libwebsock_context *
libwebsock_init(void)
{
  libwebsock_context *ctx;
  ctx = (libwebsock_context *) malloc(sizeof(libwebsock_context));
  if (!ctx) {
    fprintf(stderr, "Unable to allocate memory for libwebsock context.\n");
    return ctx;
  }
  memset(ctx, 0, sizeof(libwebsock_context));

  ctx->onclose = libwebsock_default_onclose_callback;
  ctx->onopen = libwebsock_default_onopen_callback;
  ctx->control_callback = libwebsock_default_control_callback;
  ctx->onmessage = libwebsock_default_onmessage_callback;

#ifdef _WIN32
  WSADATA WSAData;
  WSAStartup(0x101, &WSAData);
#endif

  ctx->base = event_base_new();
  if (!ctx->base) {
    free(ctx);
    fprintf(stderr, "Unable to create new event base.\n");
    return NULL;
  }

  return ctx;
}

