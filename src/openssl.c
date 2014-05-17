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

#include <unistd.h>

#include "websock.h"

void
libwebsock_handle_accept_ssl(evutil_socket_t listener, short event, void *arg)
{
  libwebsock_ssl_event_data *evdata = arg;
  libwebsock_context *ctx = evdata->ctx;
  SSL_CTX *ssl_ctx = evdata->ssl_ctx;
  libwebsock_client_state *client_state;
  struct bufferevent *bev;
  struct sockaddr_storage ss;
  socklen_t slen = sizeof(ss);
  int fd = accept(listener, (struct sockaddr *) &ss, &slen);
  if (fd < 0) {
    fprintf(stderr, "Error accepting new connection.\n");
  } else {
    client_state = (libwebsock_client_state *) lws_calloc(sizeof(libwebsock_client_state));
    client_state->sockfd = fd;
    client_state->flags |= STATE_CONNECTING | STATE_IS_SSL;
    client_state->control_callback = ctx->control_callback;
    client_state->onopen = ctx->onopen;
    client_state->onmessage = ctx->onmessage;
    client_state->onclose = ctx->onclose;
    client_state->onpong = ctx->onpong;
    client_state->sa = (struct sockaddr_storage *) lws_malloc(sizeof(struct sockaddr_storage));
    memcpy(client_state->sa, &ss, sizeof(struct sockaddr_storage));
    client_state->ssl = SSL_new(ssl_ctx);
    SSL_set_fd(client_state->ssl, fd);
    if (SSL_accept(client_state->ssl) <= 0) {
      fprintf(stderr, "error during ssl handshake.\n");
    }
    client_state->ctx = (void *) ctx;
    evutil_make_socket_nonblocking(fd);
    bev = bufferevent_openssl_socket_new(ctx->base, -1, client_state->ssl, BUFFEREVENT_SSL_OPEN, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
    client_state->bev = bev;
    bufferevent_setcb(bev, libwebsock_handshake, NULL, libwebsock_do_event, (void *) client_state);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
  }
}


void
libwebsock_bind_ssl(libwebsock_context *ctx, char *listen_host, char *port, char *keyfile, char *certfile)
{
  libwebsock_bind_ssl_real(ctx, listen_host, port, keyfile, certfile, NULL);
}


void
libwebsock_bind_ssl_real(libwebsock_context *ctx, char *listen_host, char *port, char *keyfile, char *certfile,
    char *chainfile)
{
  struct addrinfo hints, *servinfo, *p;
  struct event *listener_event;
  libwebsock_ssl_event_data *evdata;
  int sockfd, yes = 1;
  SSL_CTX *ssl_ctx;

  evdata = (libwebsock_ssl_event_data *) lws_calloc(sizeof(libwebsock_ssl_event_data));

  if (!ctx->ssl_init) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    ctx->ssl_init = 1;
  }

  ssl_ctx = SSL_CTX_new(SSLv23_server_method());
  if (!ssl_ctx) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }
  if (chainfile != NULL) {
    if (SSL_CTX_load_verify_locations(ssl_ctx, chainfile, NULL) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
  }
  if (SSL_CTX_use_certificate_file(ssl_ctx, certfile, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }
  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, keyfile, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }

  if (!SSL_CTX_check_private_key(ssl_ctx)) {
    fprintf(stderr, "Private key does not match the certificate public key.\n");
    exit(1);
  }
  memset(&hints, 0, sizeof(struct addrinfo));

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  if ((getaddrinfo(listen_host, port, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo failed during libwebsock_bind.\n");
    lws_free(ctx);
    exit(-1);
  }
  for (p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("socket");
      continue;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      perror("setsockopt");
      lws_free(ctx);
      exit(-1);
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
    lws_free(ctx);
    exit(-1);
  }

  freeaddrinfo(servinfo);

  if (listen(sockfd, LISTEN_BACKLOG) == -1) {
    perror("listen");
    exit(-1);
  }
  evdata->ssl_ctx = ssl_ctx;
  evdata->ctx = ctx;

  listener_event = event_new(ctx->base, sockfd, EV_READ | EV_PERSIST, libwebsock_handle_accept_ssl, (void *) evdata);
  event_add(listener_event, NULL);
}
