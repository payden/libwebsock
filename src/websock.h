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

#include "websock_config.h"

//this bit hides differences between systems on big-endian conversions
#if defined(__linux__)
#  include <endian.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#  include <sys/endian.h>
#elif defined(__OpenBSD__)
#  include <sys/types.h>
#  define be16toh(x) betoh16(x)
#  define be64toh(x) betoh64(x)
#endif

#ifndef be16toh
#  define be16toh(x) lws_be16toh(x)
#endif

#ifndef be64toh
#  define be64toh(x) lws_be64toh(x)
#endif

#ifndef htobe16
#  define htobe16(x) lws_htobe16(x)
#endif

#ifndef htobe64
#  define htobe64(x) lws_htobe64(x)
#endif

#ifdef _WIN32
#include <ws2tcpip.h>
#endif

#include <assert.h>
#include <stdint.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/thread.h>
#include <wchar.h>
#include <errno.h>
#ifdef WEBSOCK_HAVE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <event2/bufferevent_ssl.h>
#endif

#include <pthread.h>

#include "types.h"
#include "api.h"
#include "frames.h"
#include "default_callbacks.h"
#include "utf.h"
#include "util.h"


#define PORT_STRLEN 12
#define LISTEN_BACKLOG 10
#define FRAME_CHUNK_LENGTH 1024
#define MASK_LENGTH 4

#define WS_FRAGMENT_FIN (1 << 7)

#define WS_NONBLOCK 0x02

#define WS_OPCODE_CONTINUE 0x0
#define WS_OPCODE_TEXT 0x1
#define WS_OPCODE_BINARY 0x2
#define WS_OPCODE_CLOSE 0x8
#define WS_OPCODE_PING 0x9
#define WS_OPCODE_PONG 0xa

#define WS_CLOSE_NORMAL 1000
#define WS_CLOSE_GOING_AWAY 1001
#define WS_CLOSE_PROTOCOL_ERROR 1002
#define WS_CLOSE_NOT_ALLOWED 1003
#define WS_CLOSE_RESERVED 1004
#define WS_CLOSE_NO_CODE 1005
#define WS_CLOSE_DIRTY 1006
#define WS_CLOSE_WRONG_TYPE 1007
#define WS_CLOSE_POLICY_VIOLATION 1008
#define WS_CLOSE_MESSAGE_TOO_BIG 1009
#define WS_CLOSE_UNEXPECTED_ERROR 1011


#define STATE_SHOULD_CLOSE (1 << 0)
#define STATE_SENT_CLOSE_FRAME (1 << 1)
#define STATE_CONNECTING (1 << 2)
#define STATE_IS_SSL (1 << 3)
#define STATE_CONNECTED (1 << 4)
#define STATE_SENDING_FRAGMENT (1 << 5)
#define STATE_RECEIVING_FRAGMENT (1 << 6)
#define STATE_RECEIVED_CLOSE_FRAME (1 << 7)
#define STATE_FAILING_CONNECTION (1 << 8)

//globals
extern pthread_mutex_t global_alloc_free_lock;

//function defs


int libwebsock_send_fragment(libwebsock_client_state *state, const char *data, unsigned int len, int flags);
void libwebsock_send_cleanup(const void *data, size_t len, void *arg);
void libwebsock_cleanup_thread_list(evutil_socket_t sock, short what, void *arg);
void libwebsock_cancel_state_threads(libwebsock_client_state *state);
void libwebsock_insert_into_thread_list(libwebsock_client_state *state, pthread_t *tptr, enum WS_THREAD_TYPE type);
void libwebsock_shutdown(libwebsock_client_state *state);
void libwebsock_shutdown_after_send_cb(evutil_socket_t fd, short what, void *arg);
void libwebsock_shutdown_after_send(struct bufferevent *bev, void *arg);
void libwebsock_post_shutdown_cleanup(evutil_socket_t fd, short what, void *arg);
void libwebsock_populate_close_info_from_frame(libwebsock_close_info **info, libwebsock_frame *close_frame);
void libwebsock_fail_connection(libwebsock_client_state *state, unsigned short close_code);
void libwebsock_cleanup_context(libwebsock_context *ctx);
void libwebsock_handle_signal(evutil_socket_t sig, short event, void *ptr);
void libwebsock_handle_control_frame(libwebsock_client_state *state);
void libwebsock_dispatch_message(libwebsock_client_state *state);
void libwebsock_handle_accept(evutil_socket_t listener, short event, void *arg);
void libwebsock_handle_send(struct bufferevent *bev, void *ptr);
void libwebsock_handle_recv(struct bufferevent *bev, void *ptr);
void libwebsock_handle_client_event(libwebsock_context *ctx, libwebsock_client_state *state);
void libwebsock_do_read(struct bufferevent *bev, void *ptr);
void libwebsock_do_event(struct bufferevent *bev, short event, void *ptr);
void libwebsock_handshake_finish(struct bufferevent *bev, libwebsock_client_state *state);
void libwebsock_handshake(struct bufferevent *bev, void *ptr);
void *libwebsock_pthread_onmessage(void *arg);
void *libwebsock_pthread_onclose(void *arg);
void *libwebsock_pthread_onopen(void *arg);
void libwebsock_fragmented_add(libwebsock_fragmented *frag, char *buf, unsigned int len);
void libwebsock_fragmented_finish(libwebsock_fragmented *frag);
libwebsock_fragmented *libwebsock_fragmented_new(libwebsock_client_state *state);

#ifdef WEBSOCK_HAVE_SSL
void libwebsock_handle_accept_ssl(evutil_socket_t listener, short event, void *arg);
#endif

