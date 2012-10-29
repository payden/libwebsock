#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/epoll.h>
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

int libwebsock_send_binary(libwebsock_client_state *state, char *in_data, unsigned long long datalen) {
	int sockfd = state->sockfd;
	unsigned long long payload_len;
	unsigned char finNopcode;
	unsigned int payload_len_small;
	unsigned int payload_offset = 2;
	unsigned int len_size;
	unsigned long long be_payload_len;
	unsigned int sent = 0;
	int i;
	unsigned int frame_size;
	char *data;
	payload_len = datalen;
	finNopcode = 0x82; //FIN and binary opcode.
	if(payload_len <= 125) {
		frame_size = 2 + payload_len;
		data = (void *)malloc(frame_size);
		payload_len_small = payload_len;
	} else if(payload_len > 125 && payload_len <= 0xffff) {
		frame_size = 4 + payload_len;
		data = (void *)malloc(frame_size);
		payload_len_small = 126;
		payload_offset += 2;
	} else if(payload_len > 0xffff && payload_len <= 0xffffffffffffffffLL) {
		frame_size = 10 + payload_len;
		data = (void *)malloc(frame_size);
		payload_len_small = 127;
		payload_offset += 8;
	} else {
		fprintf(stderr, "Whoa man.  What are you trying to send?\n");
		return -1;
	}
	memset(data, 0, frame_size);
	payload_len_small &= 0x7f;
	memcpy(data, &finNopcode, 1);
	memcpy(data+1, &payload_len_small, 1); //mask bit off, 7 bit payload len
	if(payload_len_small == 126) {
		payload_len &= 0xffff;
		len_size = 2;
		for(i = 0; i < len_size; i++) {
			memcpy(data+2+i, (void *)&payload_len+(len_size-i-1), 1);
		}
	}
	if(payload_len_small == 127) {
		payload_len &= 0xffffffffffffffffLL;
		len_size = 8;
		for(i = 0; i < len_size; i++) {
			memcpy(data+2+i, (void *)&payload_len+(len_size-i-1), 1);
		}
	}
	memcpy(data+payload_offset, in_data, datalen);
	sent = 0;

	while(sent < frame_size) {
		if(state->flags & STATE_IS_SSL) {
			sent += SSL_write(state->ssl, data+sent, frame_size - sent);
		} else {
			sent += send(sockfd, data+sent, frame_size - sent, 0);
		}
	}
	free(data);
	return sent;
}

int libwebsock_send_text(libwebsock_client_state *state, char *strdata)  {
	if(strdata == NULL) {
		fprintf(stderr, "Will not send empty message.\n");
		return -1;
	}
	int sockfd = state->sockfd;
	unsigned long long payload_len;
	unsigned char finNopcode;
	unsigned int payload_len_small;
	unsigned int payload_offset = 2;
	unsigned int len_size;
	unsigned long long be_payload_len;
	unsigned int sent = 0;
	int i;
	unsigned int frame_size;
	char *data;
	payload_len = strlen(strdata);
	finNopcode = 0x81; //FIN and text opcode.
	if(payload_len <= 125) {
		frame_size = 2 + payload_len;
		data = (void *)malloc(frame_size);
		payload_len_small = payload_len;
	} else if(payload_len > 125 && payload_len <= 0xffff) {
		frame_size = 4 + payload_len;
		data = (void *)malloc(frame_size);
		payload_len_small = 126;
		payload_offset += 2;
	} else if(payload_len > 0xffff && payload_len <= 0xffffffffffffffffLL) {
		frame_size = 10 + payload_len;
		data = (void *)malloc(frame_size);
		payload_len_small = 127;
		payload_offset += 8;
	} else {
		fprintf(stderr, "Whoa man.  What are you trying to send?\n");
		return -1;
	}
	memset(data, 0, frame_size);
	payload_len_small &= 0x7f;
	memcpy(data, &finNopcode, 1);
	memcpy(data+1, &payload_len_small, 1); //mask bit off, 7 bit payload len
	if(payload_len_small == 126) {
		payload_len &= 0xffff;
		len_size = 2;
		for(i = 0; i < len_size; i++) {
			memcpy(data+2+i, (void *)&payload_len+(len_size-i-1), 1);
		}
	}
	if(payload_len_small == 127) {
		payload_len &= 0xffffffffffffffffLL;
		len_size = 8;
		for(i = 0; i < len_size; i++) {
			memcpy(data+2+i, (void *)&payload_len+(len_size-i-1), 1);
		}
	}
	memcpy(data+payload_offset, strdata, strlen(strdata));
	sent = 0;

	while(sent < frame_size) {
		if(state->flags & STATE_IS_SSL) {
			sent += SSL_write(state->ssl, data+sent, frame_size - sent);
		} else {
			sent += send(sockfd, data+sent, frame_size - sent, 0);
		}
	}
	free(data);
	return sent;
}

void libwebsock_wait(libwebsock_context *ctx) {
	int ret, i, new_fd;
	struct epoll_event ev;
	socklen_t sin_size;
	libwebsock_client_state *client_state = NULL;
	libwebsock_listener_state *listener_state = NULL;
	libwebsock_event_info *event_info = NULL;
	libwebsock_event_info *new_event_info = NULL;
	struct sockaddr_storage theiraddr;
	ctx->running = 1;
	while(ctx->running) {
		if((ret = epoll_wait(ctx->epoll_fd, ctx->events, EPOLL_EVENTS, 1000)) >= 0) {
			for(i = 0; i < ret; i++) {
				event_info = ctx->events[i].data.ptr;

				if(event_info->type == EVENT_INFO_LISTENER) {
					listener_state = (libwebsock_listener_state *)event_info->data.listener_state;
					//accepting new connection.
					sin_size = sizeof(struct sockaddr_storage);
					new_fd = accept(listener_state->sockfd, (struct sockaddr *)&theiraddr, &sin_size);

					if(new_fd != -1) {
						new_event_info = (libwebsock_event_info *)malloc(sizeof(libwebsock_event_info));
						if(!new_event_info) {
							fprintf(stderr, "Unable to allocate memory for new event container.\n");
							close(new_fd);
							return;
						}
						memset(new_event_info, 0, sizeof(libwebsock_event_info));
						new_event_info->type = EVENT_INFO_CLIENT;
						client_state = (libwebsock_client_state *)malloc(sizeof(libwebsock_client_state));
						if(!client_state) {
							fprintf(stderr, "Unable to allocate memory for new connection state structure.\n");
							free(new_event_info);
							close(new_fd);
							return;
						}

						new_event_info->data.client_state = client_state;
						memset(client_state, 0, sizeof(libwebsock_client_state));
						client_state->ei = new_event_info;
						client_state->sa = (struct sockaddr_storage *)malloc(sizeof(struct sockaddr_storage));
						if(!client_state->sa) {
							fprintf(stderr, "Error allocating memory for sockaddr_storage in libwebsock_wait.\n");
							exit(1);
						}
						memset(client_state->sa, 0, sizeof(struct sockaddr_storage));
						memcpy(client_state->sa, &theiraddr, sin_size);



						if(listener_state->flags & LISTENER_STATE_IS_SSL) {
							client_state->flags |= STATE_IS_SSL;
							client_state->ssl = SSL_new(listener_state->ssl_ctx);
							SSL_set_fd(client_state->ssl, new_fd);
							if(SSL_accept(client_state->ssl) <= 0) {
								fprintf(stderr, "Error during SSL handshake.\n");
								SSL_shutdown(client_state->ssl);
								SSL_free(client_state->ssl);
								close(new_fd);
								if(client_state->sa) {
									free(client_state->sa);
								}
								if(client_state) {
									free(client_state);
								}
								if(new_event_info) {
									free(new_event_info);
								}

								continue;
							}

						}
						client_state->flags |= STATE_CONNECTING;
						client_state->sockfd = new_fd;
						ev.events = EPOLLIN;
						ev.data.ptr = new_event_info;
						if(epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, new_fd, &ev) == -1) {
							fprintf(stderr, "Unable to add new socket (%d) to epoll\n", new_fd);
							close(new_fd);
							if(client_state) {
								free(client_state);
							}
							if(new_event_info) {
								free(new_event_info);
							}
						}
					}
				}
				else {
					client_state = (libwebsock_client_state *)event_info->data.client_state;

					libwebsock_handle_client_event(ctx, client_state);
				}
			}
		}
	}
	libwebsock_cleanup_context(ctx);
}

void libwebsock_cleanup_context(libwebsock_context *ctx) {
	libwebsock_event_info *listener_ei, *listener_ei_next;

	if(ctx->events) {
		free(ctx->events);
	}
	if(ctx->epoll_fd) {
		close(ctx->epoll_fd);
	}

	listener_ei = ctx->listener_ei;

	while(listener_ei) {
		listener_ei_next = listener_ei->next;
		if(listener_ei->data.listener_state) { //should be true if there is a pointer here, no matter what the type.. we don't care, we're freeing the mem.
			if(listener_ei->data.listener_state->ssl_ctx) {
				SSL_CTX_free(listener_ei->data.listener_state->ssl_ctx);
			}
			free(listener_ei->data.listener_state);
		}
		free(listener_ei);
		listener_ei = listener_ei_next;
	}
	free(ctx);
}

void libwebsock_bind_ssl(libwebsock_context *ctx, char *listen_host, char *port, char *keyfile, char *certfile) {
	libwebsock_bind_ssl_real(ctx, listen_host, port, keyfile, certfile, NULL);
}

void libwebsock_bind_ssl_real(libwebsock_context *ctx, char *listen_host, char *port, char *keyfile, char *certfile, char *chainfile) {
	struct addrinfo hints, *servinfo, *p;
	struct epoll_event ev;
	libwebsock_event_info *event_info;
	libwebsock_listener_state *listener_state;
	int sockfd, yes = 1;

	if(!ctx->ssl_init) {
		SSL_library_init();
		SSL_load_error_strings();
		OpenSSL_add_all_algorithms();
		ctx->ssl_init = 1;
	}

	event_info = (libwebsock_event_info *)malloc(sizeof(libwebsock_event_info));
	if(!event_info) {
		fprintf(stderr, "Unable to allocate memory for event container in libwebsock_bind.\n");
		free(ctx);
		exit(-1);
	}
	memset(event_info, 0, sizeof(libwebsock_event_info));

	listener_state = (libwebsock_listener_state *)malloc(sizeof(libwebsock_listener_state));
	if(!listener_state) {
		fprintf(stderr, "Unable to allocate memory for listener_state in libwebsock_bind.\n");
		free(event_info);
		free(ctx);
		exit(-1);
	}

	memset(listener_state, 0, sizeof(libwebsock_listener_state));



	listener_state->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if(!listener_state->ssl_ctx) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if(chainfile != NULL) {
		if(SSL_CTX_load_verify_locations(listener_state->ssl_ctx, chainfile, NULL) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}
	}
	if(SSL_CTX_use_certificate_file(listener_state->ssl_ctx, certfile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if(SSL_CTX_use_PrivateKey_file(listener_state->ssl_ctx, keyfile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}


	if(!SSL_CTX_check_private_key(listener_state->ssl_ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key.\n");
		exit(1);
	}
	memset(&hints, 0, sizeof(struct addrinfo));
	memset(&ev, 0, sizeof(struct epoll_event));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
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


	listener_state->sockfd = sockfd;
	listener_state->flags |= LISTENER_STATE_IS_SSL;
	event_info->type = EVENT_INFO_LISTENER;
	event_info->data.listener_state = listener_state;
	ev.data.ptr = event_info;
	ev.events = EPOLLIN;
	if(epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
		perror("epoll_ctl");
		free(listener_state);
		free(event_info);
		free(ctx);
		exit(-1);
	}


}

void libwebsock_bind(libwebsock_context *ctx, char *listen_host, char *port) {
	struct addrinfo hints, *servinfo, *p;
	struct epoll_event ev;
	libwebsock_event_info *event_info, *ei_ptr;
	libwebsock_listener_state *listener_state;
	int sockfd, yes = 1;
	memset(&hints, 0, sizeof(struct addrinfo));
	memset(&ev, 0, sizeof(struct epoll_event));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
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

	event_info = (libwebsock_event_info *)malloc(sizeof(libwebsock_event_info));
	if(!event_info) {
		fprintf(stderr, "Unable to allocate memory for event container in libwebsock_bind.\n");
		free(ctx);
		exit(-1);
	}
	memset(event_info, 0, sizeof(libwebsock_event_info));

	listener_state = (libwebsock_listener_state *)malloc(sizeof(libwebsock_listener_state));
	if(!listener_state) {
		fprintf(stderr, "Unable to allocate memory for listener_state in libwebsock_bind.\n");
		free(event_info);
		free(ctx);
		exit(-1);
	}

	memset(listener_state, 0, sizeof(libwebsock_listener_state));
	listener_state->sockfd = sockfd;
	event_info->type = EVENT_INFO_LISTENER;
	event_info->data.listener_state = listener_state;
	ev.data.ptr = event_info;
	ev.events = EPOLLIN;
	if(epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
		perror("epoll_ctl");
		free(listener_state);
		free(event_info);
		free(ctx);
		exit(-1);
	}
	if(!ctx->listener_ei) {
		ctx->listener_ei = event_info;
	} else {
		for(ei_ptr = ctx->listener_ei; ei_ptr->next != NULL; ei_ptr = ei_ptr->next) {};
		ei_ptr->next = event_info;
	}

}

libwebsock_context *libwebsock_init(void) {
	libwebsock_context *ctx;
	struct addrinfo hints, *servinfo = NULL, *p = NULL;
	struct epoll_event ev;
	int yes = 1;
	ctx = (libwebsock_context *)malloc(sizeof(libwebsock_context));
	if(!ctx) {
		fprintf(stderr, "Unable to allocate memory for libwebsock context.\n");
		return ctx;
	}
	memset(ctx, 0, sizeof(libwebsock_context));


	libwebsock_set_close_cb(ctx, &libwebsock_default_close_callback);
	libwebsock_set_connect_cb(ctx, &libwebsock_default_connect_callback);
	libwebsock_set_control_cb(ctx, &libwebsock_default_control_callback);
	libwebsock_set_receive_cb(ctx, &libwebsock_default_receive_callback);

	if((ctx->epoll_fd = epoll_create(EPOLL_EVENTS)) == -1) {
		perror("epoll");
		free(ctx);
		ctx = NULL;
		return ctx;
	}

	ctx->events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * EPOLL_EVENTS);
	if(!ctx->events) {
		fprintf(stderr, "Unable to allocate memory for epoll events queue.\n");
		free(ctx);
		ctx = NULL;
		return ctx;
	}
	return ctx;
}

void libwebsock_set_close_cb(libwebsock_context *ctx, int (*cb)(libwebsock_client_state *state)) {
	ctx->close_callback = cb;
}

void libwebsock_set_connect_cb(libwebsock_context *ctx, int (*cb)(libwebsock_client_state *state)) {
	ctx->connect_callback = cb;
}

void libwebsock_set_receive_cb(libwebsock_context *ctx, int (*cb)(libwebsock_client_state *state, libwebsock_message *msg)) {
	ctx->receive_callback = cb;
}

void libwebsock_set_control_cb(libwebsock_context *ctx, int (*cb)(libwebsock_client_state *state, libwebsock_frame *ctl_frame)) {
	ctx->control_callback = cb;
}
