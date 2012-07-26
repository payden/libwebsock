#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libwebsock.h"


int my_message_callback(int sockfd, libwebsock_message *msg) {
	printf("My data!!: %s\n", msg->payload);
	printf("from fd: %d\n", sockfd);
	return 0;
}

int main(int argc, char **argv) {
	libwebsock_context *ctx;
	ctx = (libwebsock_context *)libwebsock_init("3333");
	printf("Got context...\n");
	printf("Listen fd: %d\n",ctx->listen_fd);
	printf("Settings receive callback...\n");
	libwebsock_set_receive_cb(ctx, &my_message_callback);
	libwebsock_wait(ctx);
	free(ctx->events);
	free(ctx);
	return 0;
}
