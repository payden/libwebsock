#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "websock.h"



void libwebsock_dump_frame(libwebsock_frame *frame) {
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
	int i;
	fprintf(stderr, "%02x", *(frame->rawdata) & 0xff);
	for(i=1;i<frame->rawdata_idx;i++) {
		fprintf(stderr, ":%02x", *(frame->rawdata+i) & 0xff);
	}
	fprintf(stderr, "\n");
}

int libwebsock_send_binary(libwebsock_client_state *state, char *in_data, unsigned long long payload_len) {
	struct evbuffer *output = bufferevent_get_output(state->bev);
	unsigned long long payload_len_be, frame_size;
	unsigned char finNopcode, payload_len_small;
	unsigned int payload_offset = 2;
	unsigned int len_size;
	unsigned int sent = 0;
	int i;
	char *data;
	payload_len_be = htobe64(payload_len);
	finNopcode = 0x82; //FIN and binary opcode.
	if(payload_len <= 125) {
		frame_size = 2 + payload_len;
		payload_len_small = payload_len;
	} else if(payload_len > 125 && payload_len <= 0xffff) {
		frame_size = 4 + payload_len;
		payload_len_small = 126;
		payload_offset += 2;
	} else if(payload_len > 0xffff && payload_len <= 0xffffffffffffffffLL) {
		frame_size = 10 + payload_len;
		payload_len_small = 127;
		payload_offset += 8;
	} else {
		fprintf(stderr, "Whoa man.  What are you trying to send?\n");
		return -1;
	}
	data = (char *)malloc(frame_size);
	memset(data, 0, frame_size);
	payload_len_small &= 0x7f;
	*data = finNopcode;
	*(data+1) = payload_len_small;
	if(payload_len_small == 126) {
		payload_len &= 0xffff;
		len_size = 2;
		memcpy(data+2, &payload_len_be, len_size);
	}
	if(payload_len_small == 127) {
		payload_len &= 0xffffffffffffffffLL;
		len_size = 8;
		memcpy(data+2, &payload_len_be, len_size);
	}
	memcpy(data+payload_offset, in_data, payload_len);

	sent = evbuffer_add(output, data, frame_size);

	free(data);
	return sent;
}

int libwebsock_send_text(libwebsock_client_state *state, char *strdata)  {
	if(strdata == NULL) {
		fprintf(stderr, "Will not send empty message.\n");
		return -1;
	}

	struct evbuffer *output = bufferevent_get_output(state->bev);
	unsigned long long payload_len, payload_len_be;
	unsigned char finNopcode, payload_len_small;
	unsigned int payload_offset = 2;
	unsigned int len_size;
	unsigned long long be_payload_len;
	unsigned int sent = 0;
	unsigned int frame_size;
	int i;
	char *data;
	payload_len = strlen(strdata);
	payload_len_be = htobe64(payload_len);

	fprintf(stderr, "\n");
	finNopcode = 0x81; //FIN and text opcode.
	if(payload_len <= 125) {
		frame_size = 2 + payload_len;
		payload_len_small = payload_len;
	} else if(payload_len > 125 && payload_len <= 0xffff) {
		frame_size = 4 + payload_len;
		payload_len_small = 126;
		payload_offset += 2;
	} else if(payload_len > 0xffff && payload_len <= 0xffffffffffffffffLL) {
		frame_size = 10 + payload_len;
		payload_len_small = 127;
		payload_offset += 8;
	} else {
		fprintf(stderr, "Whoa man.  What are you trying to send?\n");
		return -1;
	}
	data = (char *)malloc(frame_size);
	memset(data, 0, frame_size);
	payload_len_small &= 0x7f;
	*data = finNopcode;
	*(data+1) = payload_len_small;
	if(payload_len_small == 126) {
		payload_len &= 0xffff;
		len_size = 2;
		memcpy(data+2, &payload_len_be, len_size);
	}
	if(payload_len_small == 127) {
		payload_len &= 0xffffffffffffffffLL;
		len_size = 8;
		memcpy(data+2, &payload_len_be, len_size);
	}
	memcpy(data+payload_offset, strdata, strlen(strdata));

	sent = evbuffer_add(output, data, frame_size);

	free(data);
	return sent;
}

void libwebsock_wait(libwebsock_context *ctx) {
	struct event *sig_event;
	sig_event = evsignal_new(ctx->base, SIGINT, libwebsock_handle_signal, (void *)ctx);
	event_add(sig_event, NULL);
	ctx->running = 1;
	event_base_dispatch(ctx->base);
	ctx->running = 0;
	event_free(sig_event);
}

void libwebsock_cleanup_context(libwebsock_context *ctx) {
	free(ctx);
}


void libwebsock_bind_ssl(libwebsock_context *ctx, char *listen_host, char *port, char *keyfile, char *certfile) {
	libwebsock_bind_ssl_real(ctx, listen_host, port, keyfile, certfile, NULL);
}


void libwebsock_bind_ssl_real(libwebsock_context *ctx, char *listen_host, char *port, char *keyfile, char *certfile, char *chainfile) {
	struct addrinfo hints, *servinfo, *p;
	struct event *listener_event;
	libwebsock_ssl_event_data *evdata;
	int sockfd, yes = 1;
	SSL_CTX *ssl_ctx;

	evdata = (libwebsock_ssl_event_data *)malloc(sizeof(libwebsock_ssl_event_data));
	if(!evdata) {
		fprintf(stderr, "Unable to allocate memory for ssl_event_data.\n");
		exit(1);
	}
	memset(evdata, 0, sizeof(libwebsock_ssl_event_data));

	if(!ctx->ssl_init) {
		SSL_library_init();
		SSL_load_error_strings();
		OpenSSL_add_all_algorithms();
		ctx->ssl_init = 1;
	}

	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if(!ssl_ctx) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if(chainfile != NULL) {
		if(SSL_CTX_load_verify_locations(ssl_ctx, chainfile, NULL) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}
	}
	if(SSL_CTX_use_certificate_file(ssl_ctx, certfile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if(SSL_CTX_use_PrivateKey_file(ssl_ctx, keyfile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}


	if(!SSL_CTX_check_private_key(ssl_ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key.\n");
		exit(1);
	}
	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if((getaddrinfo(listen_host, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo failed during libwebsock_bind.\n");
		free(ctx);
		exit(-1);
	}
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("socket");
			continue;
		}
		if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("setsockopt");
			free(ctx);
			exit(-1);
		}
		if(bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("bind");
			close(sockfd);
			continue;
		}
		break;
	}

	if(p == NULL) {
		fprintf(stderr, "Failed to bind to address and port.  Exiting.\n");
		free(ctx);
		exit(-1);
	}

	freeaddrinfo(servinfo);

	if(listen(sockfd, LISTEN_BACKLOG) == -1) {
		perror("listen");
		exit(-1);
	}
	evdata->ssl_ctx = ssl_ctx;
	evdata->ctx = ctx;

	listener_event = event_new(ctx->base, sockfd, EV_READ | EV_PERSIST, libwebsock_handle_accept_ssl, (void *)evdata);
	event_add(listener_event, NULL);
}

void libwebsock_bind(libwebsock_context *ctx, char *listen_host, char *port) {
	struct addrinfo hints, *servinfo, *p;
	struct event *listener_event;

	evutil_socket_t sockfd;
	int yes = 1;
	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if((getaddrinfo(listen_host, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo failed during libwebsock_bind.\n");
		free(ctx);
		exit(-1);
	}
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("socket");
			continue;
		}

		evutil_make_socket_nonblocking(sockfd);

		if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("setsockopt");
			free(ctx);
			exit(-1);
		}
		if(bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("bind");
			close(sockfd);
			continue;
		}
		break;
	}

	if(p == NULL) {
		fprintf(stderr, "Failed to bind to address and port.  Exiting.\n");
		free(ctx);
		exit(-1);
	}

	freeaddrinfo(servinfo);

	if(listen(sockfd, LISTEN_BACKLOG) == -1) {
		perror("listen");
		exit(-1);
	}

	listener_event = event_new(ctx->base, sockfd, EV_READ | EV_PERSIST, libwebsock_handle_accept, (void *)ctx);
	event_add(listener_event, NULL);
}

libwebsock_context *libwebsock_init(void) {
	libwebsock_context *ctx;
	struct addrinfo hints, *servinfo = NULL, *p = NULL;
	int yes = 1;
	ctx = (libwebsock_context *)malloc(sizeof(libwebsock_context));
	if(!ctx) {
		fprintf(stderr, "Unable to allocate memory for libwebsock context.\n");
		return ctx;
	}
	memset(ctx, 0, sizeof(libwebsock_context));


	ctx->onclose = &libwebsock_default_onclose_callback;
	ctx->onopen = &libwebsock_default_onopen_callback;
	ctx->control_callback = &libwebsock_default_control_callback;
	ctx->onmessage = &libwebsock_default_onmessage_callback;

	ctx->base = event_base_new();
	if(!ctx->base) {
		fprintf(stderr, "Unable to create new event base.\n");
		exit(1);
	}

	return ctx;
}

