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

#include "config.h"

//this bit hides differences between systems on big-endian conversions
#if defined(__linux__)
#  include <endian.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#  include <sys/endian.h>
#elif defined(__OpenBSD__)
#  include <sys/types.h>
#  define be16toh(x) betoh16(x)
#  define be32toh(x) betoh32(x)
#  define be64toh(x) betoh64(x)
#endif


#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#ifdef WEBSOCK_HAVE_SSL
#include <openssl/ssl.h>
#include <event2/bufferevent_ssl.h>
#endif


#define PORT_STRLEN 12
#define LISTEN_BACKLOG 10
#define FRAME_CHUNK_LENGTH 1024
#define MASK_LENGTH 4

#define WS_FRAGMENT_FIN (1 << 7)

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


typedef struct _libwebsock_string {
	char *data;
	int length;
	int idx;
	int data_sz;
} libwebsock_string;

typedef struct _libwebsock_frame {
	unsigned int fin;
	unsigned int opcode;
	unsigned int mask_offset;
	unsigned int payload_offset;
	unsigned int rawdata_idx;
	unsigned int rawdata_sz;
	unsigned int payload_len_short;
	unsigned long long payload_len;
	char *rawdata;
	struct _libwebsock_frame *next_frame;
	struct _libwebsock_frame *prev_frame;
	unsigned char mask[4];
	int state;
} libwebsock_frame;

typedef struct _libwebsock_message {
	unsigned int opcode;
	unsigned long long payload_len;
	char *payload;
} libwebsock_message;

typedef struct _libwebsock_close_info {
	unsigned short code;
	char reason[124];
} libwebsock_close_info;

typedef struct _libwebsock_client_state {
	int sockfd;
	int flags;
	void *data;
	libwebsock_frame *current_frame;
	struct sockaddr_storage *sa;
	struct bufferevent *bev;
	int (*onmessage)(struct _libwebsock_client_state *, libwebsock_message *);
	int (*control_callback)(struct _libwebsock_client_state *, libwebsock_frame *);
	int (*onopen)(struct _libwebsock_client_state *);
	int (*onclose)(struct _libwebsock_client_state *);
#ifdef WEBSOCK_HAVE_SSL
	SSL *ssl;
#endif
	libwebsock_close_info *close_info;
} libwebsock_client_state;

typedef struct _libwebsock_context {
	int running;
	int ssl_init;
	struct event_base *base;
	int (*onmessage)(libwebsock_client_state *, libwebsock_message *);
	int (*control_callback)(libwebsock_client_state *, libwebsock_frame *);
	int (*onopen)(libwebsock_client_state *);
	int (*onclose)(libwebsock_client_state *);
} libwebsock_context;


typedef struct _libwebsock_fragmented {
	char *send;
	char *queued;
	unsigned int send_len;
	unsigned int queued_len;
	struct _libwebsock_client_state *state;
} libwebsock_fragmented;

#ifdef WEBSOCK_HAVE_SSL
typedef struct _libwebsock_ssl_event_data {
	SSL_CTX *ssl_ctx;
	libwebsock_context *ctx;
} libwebsock_ssl_event_data;
#endif


//function defs

int libwebsock_close(libwebsock_client_state *state);
int libwebsock_close_with_reason(libwebsock_client_state *state, unsigned short code, const char *reason);
int libwebsock_send_fragment(libwebsock_client_state *state, const char *data, unsigned long long len, int flags);
int libwebsock_send_binary(libwebsock_client_state *state, char *in_data, unsigned long long payload_len);
int libwebsock_send_text(libwebsock_client_state *state, char *strdata);
int libwebsock_complete_frame(libwebsock_frame *frame);
int libwebsock_default_onclose_callback(libwebsock_client_state *state);
int libwebsock_default_onopen_callback(libwebsock_client_state *state);
int libwebsock_default_onmessage_callback(libwebsock_client_state *state, libwebsock_message *msg);
int libwebsock_default_control_callback(libwebsock_client_state *state, libwebsock_frame *ctl_frame);
void libwebsock_populate_close_info_from_frame(libwebsock_close_info **info, libwebsock_frame *close_frame);
void libwebsock_fail_connection(libwebsock_client_state *state);
void libwebsock_cleanup_context(libwebsock_context *ctx);
void libwebsock_handle_signal(evutil_socket_t sig, short event, void *ptr);
void libwebsock_handle_control_frame(libwebsock_client_state *state, libwebsock_frame *ctl_frame);
void libwebsock_dispatch_message(libwebsock_client_state *state, libwebsock_frame *current);
void libwebsock_dump_frame(libwebsock_frame *frame);
void libwebsock_handle_accept(evutil_socket_t listener, short event, void *arg);
void libwebsock_handle_send(struct bufferevent *bev, void *ptr);
void libwebsock_handle_recv(struct bufferevent *bev, void *ptr);
void libwebsock_handle_client_event(libwebsock_context *ctx, libwebsock_client_state *state);
void libwebsock_do_read(struct bufferevent *bev, void *ptr);
void libwebsock_do_event(struct bufferevent *bev, short event, void *ptr);
void libwebsock_wait(libwebsock_context *ctx);
void libwebsock_handshake_finish(struct bufferevent *bev, libwebsock_client_state *state);
void libwebsock_handshake(struct bufferevent *bev, void *ptr);
void libwebsock_bind(libwebsock_context *ctx, char *listen_host, char *port);
void libwebsock_fragmented_add(libwebsock_fragmented *frag, char *buf, unsigned int len);
void libwebsock_fragmented_finish(libwebsock_fragmented *frag);
libwebsock_fragmented *libwebsock_fragmented_new(libwebsock_client_state *state);
libwebsock_context *libwebsock_init(void);

#ifdef WEBSOCK_HAVE_SSL
void libwebsock_bind_ssl(libwebsock_context *ctx, char *listen_host, char *port, char *keyfile, char *certfile);
void libwebsock_bind_ssl_real(libwebsock_context *ctx, char *listen_host, char *port, char *keyfile, char *certfile, char *chainfile);
void libwebsock_handle_accept_ssl(evutil_socket_t listener, short event, void *arg);
#endif

