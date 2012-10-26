#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "websock.h"

void libwebsock_free_all_frames(libwebsock_client_state *state) {
	libwebsock_frame *current, *next;
	if(state != NULL) {
		current = state->current_frame;
		if(current) {
			for(;current->prev_frame != NULL; current = current->prev_frame) {}; //rewind
			while(current != NULL) {
				next = current->next_frame;
				if(current->rawdata) {
					free(current->rawdata);
				}
				free(current);
				current = next;
			}
		}
	}
}

void libwebsock_handle_control_frame(libwebsock_context *ctx, libwebsock_client_state *state, libwebsock_frame *ctl_frame) {
	libwebsock_frame *ptr = NULL;
	ctx->control_callback(state, ctl_frame);
	//the idea here is to reset this frame to the state it was in before we received control frame.
	// Control frames can be injected in the midst of a fragmented message.
	// We need to maintain the link to previous frame if present.
	// It should be noted that ctl_frame is still state->current_frame after this function returns.
	// So even though the below refers to ctl_frame, I'm really setting up state->current_frame to continue receiving data on the next go 'round
	ptr = ctl_frame->prev_frame; //This very well may be a NULL pointer, but just in case we preserve it.
	free(ctl_frame->rawdata);
	memset(ctl_frame, 0, sizeof(libwebsock_frame));
	ctl_frame->prev_frame = ptr;
	ctl_frame->rawdata = (char *)malloc(FRAME_CHUNK_LENGTH);
	memset(ctl_frame->rawdata, 0, FRAME_CHUNK_LENGTH);
}

void libwebsock_cleanup_frames(libwebsock_frame *first) {
	libwebsock_frame *this = NULL;
	libwebsock_frame *next = first;
	while(next != NULL) {
		this = next;
		next = this->next_frame;
		if(this->rawdata != NULL) {
			free(this->rawdata);
		}
		free(this);
	}
}

int libwebsock_complete_frame(libwebsock_frame *frame) {
	int payload_len_short, i;
	unsigned long long payload_len = 0;
	if(frame->rawdata_idx < 2) {
		return 0;
	}
	frame->mask_offset = 2;
	frame->fin = (*(frame->rawdata) & 0x80) == 0x80 ? 1 : 0;
	frame->opcode = *(frame->rawdata) & 0x0f;
	if((*(frame->rawdata+1) & 0x80) != 0x80) { //unmasked frame, fail connection.
		return -1;
	}
	payload_len_short = *(frame->rawdata+1) & 0x7f;
	switch(payload_len_short) {
	case 126:
		if(frame->rawdata_idx < 4) {
			fprintf(stderr, "Frame has 16 bit payload len, but not enough bytes to read it yet.\n");
			return 0;
		}
		for(i = 0; i < 2; i++) {
			memcpy((void *)&payload_len+i, frame->rawdata+3-i, 1);
		}
		frame->mask_offset += 2;
		frame->payload_len = payload_len;
		break;
	case 127:
		if(frame->rawdata_idx < 10) {
			fprintf(stderr, "Frame has 64 bit payload len, but not enough bytes to read it yet.\n");
			return 0;
		}
		for(i = 0; i < 8; i++) {
			memcpy((void *)&payload_len+i, frame->rawdata+9-i, 1);
		}
		frame->mask_offset += 8;
		frame->payload_len = payload_len;
		break;
	default:
		frame->payload_len = payload_len_short;
		break;

	}
	frame->payload_offset = frame->mask_offset + MASK_LENGTH;
	if(frame->rawdata_idx < frame->payload_offset + frame->payload_len) {
		return 0;
	}
	for(i = 0; i < MASK_LENGTH; i++) {
		frame->mask[i] = *(frame->rawdata + frame->mask_offset + i) & 0xff;
	}
	return 1;
}
