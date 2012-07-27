#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libwebsock.h"


/*

Define message callback with same prototype as below.
Accepts int for socket descriptor (unique to client) and libwebsock_message structure.
libwebsock_message has unsigned int opcode, unsigned long long payload_len, and char *payload

*/
int my_message_callback(int sockfd, libwebsock_message *msg) {
	printf("Received message from %d\n",sockfd);
	printf("Opcode: %d\n",msg->opcode);
	printf("Payload length: %llu\n", msg->payload_len);
	libwebsock_send_text(sockfd, msg->payload);
	return 0;
}

int main(int argc, char **argv) {
	libwebsock_context *ctx;
	ctx = (libwebsock_context *)libwebsock_init("3333");
	libwebsock_set_receive_cb(ctx, &my_message_callback);
	libwebsock_wait(ctx);
	free(ctx->events);
	free(ctx);
	return 0;
}
