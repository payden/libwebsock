#include <stdio.h>
#include <stdlib.h>

#include <websock/websock.h>


/*

Define message callback with same prototype as below.
Accepts pointer to libwebsock_client_state structure and pointer to libwebsock_message structure.
libwebsock_client_state has int sockfd, int sent_close_frame, int should_close, and libwebsock_frame *current_frame
libwebsock_message has unsigned int opcode, unsigned long long payload_len, and char *payload

You probably shouldn't modify any of the data contained in the structures passed to the callback.  It will probably cause bad things to happen.
You can, of course, make copies of the data contained therein.

Here is the default receive_callback as an example:
(libwebsock_send_text accepts socket descriptor and character array)

int some_callback_name(libwebsock_client_state *state, libwebsock_message *msg) {
	libwebsock_send_text(state->sockfd, msg->payload);
	return 0;
}

This callback just provides echoing messages back to the websocket client.

You would register this callback via:

libwebsock_set_receive_cb(ctx, &some_callback_name);



*/


//Here is a little more verbose version of the echo server.

int my_receive_callback(libwebsock_client_state *state, libwebsock_message *msg) {
	printf("Socket Descriptor: %d\n", state->sockfd);
	printf("Message opcode: %d\n", msg->opcode);
	printf("Payload Length: %llu\n", msg->payload_len);
	printf("Payload: %s\n", msg->payload);
	//now let's send it back.
	libwebsock_send_text(state->sockfd, msg->payload);
}

int main(int argc, char **argv) {
	libwebsock_context *ctx = NULL;
	ctx = (libwebsock_context *)libwebsock_init();
	if(ctx == NULL) {
		fprintf(stderr, "Error during libwebsock_init.\n");
		exit(1);
	}
	libwebsock_bind(ctx, "0.0.0.0", "3333");
	libwebsock_set_receive_cb(ctx, &my_receive_callback);
	libwebsock_wait(ctx);
	return 0;
}
