#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>

#include "websock.h"
#include "sha1.h"
#include "base64.h"


void libwebsock_handle_client_event(libwebsock_context *ctx, libwebsock_client_state *state) {
	char buf[1024];
	char *newdata = NULL;
	int n;
	memset(buf, 0, 1024);
	if(state->flags & STATE_IS_SSL) {
		n = SSL_read(state->ssl, buf, 1023);

	} else {
		n = recv(state->sockfd, buf, 1023, 0);
	}
	if(n == -1) {
		fprintf(stderr, "Error occurred during receive in libwebsock_handle_client_event.\n");
		return;
	}
	if(n == 0) {
		if(ctx->close_callback != NULL) {
			ctx->close_callback(state);
		}
		libwebsock_free_all_frames(state);
		if(state->flags & STATE_IS_SSL) {
			SSL_shutdown(state->ssl);
			SSL_free(state->ssl);
		}
		close(state->sockfd);
		if(state->sa) {
			free(state->sa);
		}
		free(state);
		return;
	}
	newdata = (char *)malloc(n+1);
	if(newdata == NULL) {
		fprintf(stderr, "Unable to allocate memory in libwebsock_handle_client_event\n");
		exit(1);
	}
	memset(newdata, 0, n+1);
	memcpy(newdata, buf, n);
	if(state->flags & STATE_CONNECTING) {
		libwebsock_handshake(ctx, state, newdata, n);
	} else {
		libwebsock_handle_recv(ctx, state, newdata, n);
	}

}

void libwebsock_handle_recv(libwebsock_context *ctx, libwebsock_client_state *state, char *data, int datalen) {
	//alright... while we haven't reached the end of data keep trying to build frames
	//possible states right now:
	// 1.) we're receiving the beginning of a new frame
	// 2.) we're receiving more data from a frame that was created previously and was not complete
	int i;
	for(i=0;i<datalen;i++) {
		libwebsock_in_data(ctx, state, *(data+i));
	}
	free(data);

}

void libwebsock_dispatch_message(libwebsock_context *ctx, libwebsock_client_state *state, libwebsock_frame *current) {
	unsigned long long message_payload_len, message_offset;
	int message_opcode, i;
	char *message_payload;
	libwebsock_frame *first = NULL;
	libwebsock_message *msg = NULL;
	if(current == NULL) {
		fprintf(stderr, "Somehow, null pointer passed to libwebsock_dispatch_message.\n");
		exit(1);
	}
	message_offset = 0;
	message_payload_len = current->payload_len;
	for(;current->prev_frame != NULL;current = current->prev_frame) {
		message_payload_len += current->payload_len;
	}
	first = current;
	message_opcode = current->opcode;
	message_payload = (char *)malloc(message_payload_len + 1);
	memset(message_payload, 0, message_payload_len + 1);
	for(;current != NULL; current = current->next_frame) {
		for(i = 0; i < current->payload_len; i++) {
			*(current->rawdata + current->payload_offset + i) ^= (current->mask[i % 4] & 0xff);
		}
		memcpy(message_payload + message_offset, current->rawdata + current->payload_offset, current->payload_len);
		message_offset += current->payload_len;
	}

	libwebsock_cleanup_frames(first);

	msg = (libwebsock_message *)malloc(sizeof(libwebsock_message));
	memset(msg, 0, sizeof(libwebsock_message));
	msg->opcode = message_opcode;
	msg->payload_len = message_offset;
	msg->payload = message_payload;
	if(ctx->receive_callback != NULL) {
		ctx->receive_callback(state, msg);
	} else {
		fprintf(stderr, "No received call back registered with libwebsock.\n");
	}
	free(msg->payload);
	free(msg);
}

void libwebsock_handshake_finish(libwebsock_context *ctx, libwebsock_client_state *state) {
	libwebsock_string *str = state->data;
	char buf[1024];
	char sha1buf[45];
	char concat[1024];
	unsigned char sha1mac[20];
	char *tok = NULL, *headers = NULL, *key = NULL;
	char *base64buf = NULL;
	const char *GID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	struct epoll_event ev;
	int sockfd = state->sockfd;
	SHA1Context shactx;
	SHA1Reset(&shactx);
	int n = 0;
	int x = 0;
	
	headers = (char *)malloc(str->data_sz);
	if(!headers) {
		fprintf(stderr, "Unable to allocate memory in libwebsock_handshake..\n");
		close(sockfd);
		return;
	}
	memset(headers, 0, str->data_sz);
	strncpy(headers, str->data, str->idx);
	for(tok = strtok(headers, "\r\n"); tok != NULL; tok = strtok(NULL, "\r\n")) {
		if(strstr(tok, "Sec-WebSocket-Key: ") != NULL) {
			key = (char *)malloc(strlen(tok));
			strncpy(key, tok+strlen("Sec-WebSocket-Key: "), strlen(tok));
			break;
		}
	}

	
	if(key == NULL) {
		fprintf(stderr, "Unable to find key in request headers.\n");
		state->flags |= STATE_SHOULD_CLOSE;
		return;
	}


	memset(concat, 0, sizeof(concat));
	strncat(concat, key, strlen(key));
	strncat(concat, GID, strlen(GID));
	SHA1Input(&shactx, (unsigned char *)concat, strlen(concat));
	SHA1Result(&shactx);
	free(key);
	key = NULL;
	sprintf(sha1buf, "%08x%08x%08x%08x%08x", shactx.Message_Digest[0], shactx.Message_Digest[1], shactx.Message_Digest[2], shactx.Message_Digest[3], shactx.Message_Digest[4]);
	for(n = 0; n < (strlen(sha1buf)/2);n++)
		sscanf(sha1buf+(n*2), "%02hhx", sha1mac+n);
	base64buf = (char *)malloc(256);
	base64_encode(sha1mac, 20, base64buf, 256);
	memset(buf, 0, 1024);
	snprintf(buf, 1024, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64buf);
	for(n = 0; n < strlen(buf);) {
		if(state->flags & STATE_IS_SSL) {
			x = SSL_write(state->ssl, buf+n, strlen(buf+n));
		} else {
			x = send(sockfd, buf+n, strlen(buf+n), 0);
		}
		if(x == -1 || x == 0)
			break;
		n += x;
	}

	state->flags &= ~STATE_CONNECTING;

	if(ctx->connect_callback != NULL) {
		ctx->connect_callback(state);
	}
}

void libwebsock_handshake(libwebsock_context *ctx, libwebsock_client_state *state, char *data, int datalen) {
	libwebsock_string *str = NULL;
	str = state->data;
	if(!str) {
		state->data = (libwebsock_string *)malloc(sizeof(libwebsock_string));
		if(!state->data) {
			fprintf(stderr, "Unable to allocate memory in libwebsock_handshake.\n");
			state->flags |= STATE_SHOULD_CLOSE;
			return;
		}
		str = state->data;
		memset(str, 0, sizeof(libwebsock_string));
		str->data_sz = FRAME_CHUNK_LENGTH;
		str->data = (char *)malloc(str->data_sz);
		if(!str->data) {
			fprintf(stderr, "Unable to allocate memory in libwebsock_handshake.\n");
			state->flags |= STATE_SHOULD_CLOSE;
			return;
		}
		memset(str->data, 0, str->data_sz);
	}

	if(str->idx + datalen + 1 >= str->data_sz) {
		str->data = realloc(str->data, str->data_sz + FRAME_CHUNK_LENGTH);
		if(!str->data) {
			fprintf(stderr, "Failed realloc.\n");
			state->flags |= STATE_SHOULD_CLOSE;
			return;
		}
		str->data_sz += FRAME_CHUNK_LENGTH;
		memset(str->data + str->idx, 0, str->data_sz - str->idx);
	}
	memcpy(str->data + str->idx, data, datalen);
	str->idx += datalen;
	if(strstr(str->data, "\r\n\r\n") != NULL) {
		libwebsock_handshake_finish(ctx, state);
	}
}

void libwebsock_shutdown(libwebsock_context *ctx) {
	free(ctx->events);
	free(ctx);
}


