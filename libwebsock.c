#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "libwebsock.h"
#include "sha1.h"
#include "base64.h"

void libwebsock_wait(libwebsock_context *ctx) {
	int ret, i, new_fd;
	socklen_t sin_size;
	struct epoll_event ev;
	struct sockaddr_storage theiraddr;
	while((ret = epoll_wait(ctx->epoll_fd, ctx->events, EPOLL_EVENTS, 1000)) >= 0) {
		for(i = 0; i < ret; i++) {
			if(ctx->events[i].data.fd == ctx->listen_fd) {
				//accepting new connection.
				new_fd = accept(ctx->listen_fd, (struct sockaddr *)&theiraddr, &sin_size);
				if(new_fd != -1) {
					fprintf(stderr, "Debug: accepted new connection...\n");
					libwebsock_handshake(ctx, new_fd);	
				}
			}
			else {
				//handle io on fd
			}
		}
	}
}

void libwebsock_handshake(libwebsock_context *ctx, int sockfd) {
	//probably shouldn't have a static size for handshake buffer, maybe some better programmers can learn me in this.
	char buf[1024];
	char sha1buf[45];
	unsigned char sha1mac[20];
	char *concat = NULL;
	char *base64buf = NULL;
	const char *GID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	struct epoll_event ev;
	SHA1Context shactx;
	SHA1Reset(&shactx);
	memset(buf, 0, 1024);
	int n = 0;
	int x = 0;
	int endheader = 0;
	while(endheader == 0) {
		n = recv(sockfd, &buf[x], 1023, 0);
		if(strcmp(&buf[x+(n-4)], "\r\n\r\n") == 0) {
			endheader = 1;
		}
		x += n;
	}
	
	char *tok = NULL, *headers = NULL, *key = NULL;
	headers = (char *)malloc(1024);
	if(!headers) {
		fprintf(stderr, "Unable to allocate memory in libwebsock_handshake..\n");
		close(sockfd);
		return;
	}
	strncpy(headers, buf, 1023);
	for(tok = strtok(headers, "\r\n"); tok != NULL; tok = strtok(NULL, "\r\n")) {
		if(strstr(tok, "Sec-WebSocket-Key: ") != NULL) {
			key = (char *)malloc(strlen(tok));
			strncpy(key, tok+strlen("Sec-WebSocket-Key: "), strlen(tok));
			break;
		}
	}

	
	if(key == NULL) {
		fprintf(stderr, "Unable to find key in request headers.\n");
		close(sockfd);
		return;
	}

	concat = (char *)malloc(strlen(GID) + strlen(key) + 1);
	strncpy(concat, key, strlen(key));
	strncat(concat, GID, strlen(GID));
	SHA1Input(&shactx, (unsigned char *)concat, strlen(concat));
	SHA1Result(&shactx);
	free(concat);
	free(key);
	key = concat = NULL;
	sprintf(sha1buf, "%08x%08x%08x%08x%08x", shactx.Message_Digest[0], shactx.Message_Digest[1], shactx.Message_Digest[2], shactx.Message_Digest[3], shactx.Message_Digest[4]);
	for(n = 0; n < (strlen(sha1buf)/2);n++)
		sscanf(sha1buf+(n*2), "%02hhx", sha1mac+n);
	base64buf = (char *)malloc(256);
	base64_encode(sha1mac, 20, base64buf, 256);
	memset(buf, 0, 1024);
	snprintf(buf, 1024, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64buf);
	for(n = 0; n < strlen(buf);)
		n += send(sockfd, buf+n, strlen(buf+n), 0);
	ev.data.fd = sockfd;
	ev.events = EPOLLIN;
	epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, sockfd, &ev);
}

void libwebsock_set_receive_cb(libwebsock_context *ctx, int (*cb)(int, libwebsock_message* msg)) {
	ctx->received_callback = cb;
}

libwebsock_context *libwebsock_init(char *port) {
	libwebsock_context *ctx;
	struct addrinfo hints, *servinfo = NULL, *p = NULL;
	struct epoll_event ev;
	socklen_t sin_size;
	int yes = 1;
	ctx = (libwebsock_context *)malloc(sizeof(libwebsock_context));
	if(!ctx) {
		fprintf(stderr, "Unable to allocate memory for libwebsock context.\n");
		return ctx;
	}
	memset(ctx, 0, sizeof(libwebsock_context));
	strncpy(ctx->port, port, PORT_STRLEN);
	if((ctx->epoll_fd = epoll_create(EPOLL_EVENTS)) == -1) {
		perror("epoll");
		free(ctx);
		ctx = NULL;
		return ctx;
	}
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if((getaddrinfo(NULL, ctx->port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo failed\n");
		free(ctx);
		ctx = NULL;
		return ctx;
	}
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if((ctx->listen_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("socket");
			continue;
		}
		if(setsockopt(ctx->listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("setsockopt");
			free(ctx);
			ctx = NULL;
			return ctx;
		}
		if(bind(ctx->listen_fd, p->ai_addr, p->ai_addrlen) == -1) {
			close(ctx->listen_fd);
			perror("bind");
			continue;
		}
		break;
	}
	
	if(p == NULL) {
		fprintf(stderr, "Failed to bind..\n");
		free(ctx);
		ctx = NULL;
		return ctx;
	}

	freeaddrinfo(servinfo);
	
	if(listen(ctx->listen_fd, LISTEN_BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	ev.data.fd = ctx->listen_fd;
	ev.events = EPOLLIN;
	if(epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->listen_fd, &ev) == -1) {
		perror("epoll_ctl");
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
