#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "websock.h"

int libwebsock_default_onclose_callback(libwebsock_client_state *state) {
	fprintf(stderr, "Closing connection with socket descriptor: %d\n", state->sockfd);
	return 0;
}

int libwebsock_default_onopen_callback(libwebsock_client_state *state) {
	fprintf(stderr, "New connection with socket descriptor: %d\n", state->sockfd);
	return 0;
}

int libwebsock_default_onmessage_callback(libwebsock_client_state *state, libwebsock_message *msg) {
	libwebsock_send_text(state, msg->payload);
	return 0;
}

int libwebsock_default_control_callback(libwebsock_client_state *state, libwebsock_frame *ctl_frame) {
	struct evbuffer *output = bufferevent_get_output(state->bev);
	int i;
	switch(ctl_frame->opcode) {
		case WS_OPCODE_CLOSE:  //close frame
			for(i=0;i<ctl_frame->payload_len;i++) {
				*(ctl_frame->rawdata + ctl_frame->payload_offset + i) ^= (ctl_frame->mask[i % 4] & 0xff); //demask payload
			}
			if((state->flags & STATE_SENT_CLOSE_FRAME) == 0) {
				//client request close.  Echo close frame as acknowledgement
				*(ctl_frame->rawdata + 1) &= 0x7f; //strip mask bit
				evbuffer_add(output, ctl_frame->rawdata, ctl_frame->payload_offset + ctl_frame->payload_len);
			}
			if(!state->close_info && ctl_frame->payload_len >= 2) {
				libwebsock_populate_close_info_from_frame(&state->close_info, ctl_frame);
			}
			state->flags |= STATE_SHOULD_CLOSE;
			break;
	}
	return 1;
}
