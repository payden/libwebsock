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

#ifndef TYPES_H_
#define TYPES_H_

enum WS_FRAME_STATE {
        sw_start = 0,
        sw_got_two,
        sw_got_short_len,
        sw_got_full_len,
        sw_loaded_mask
};

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
        enum WS_FRAME_STATE state;
} libwebsock_frame;

typedef struct _libwebsock_string {
        char *data;
        int length;
        int idx;
        int data_sz;
} libwebsock_string;

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

#endif /* TYPES_H_ */
