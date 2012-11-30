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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "websock.h"

void
libwebsock_free_all_frames(libwebsock_client_state *state)
{
  libwebsock_frame *current, *next;
  if (state != NULL) {
    current = state->current_frame;
    if (current) {
      for (; current->prev_frame != NULL; current = current->prev_frame);
      while (current != NULL) {
        next = current->next_frame;
        if (current->rawdata) {
          free(current->rawdata);
        }
        free(current);
        current = next;
      }
    }
  }
}

void
libwebsock_handle_control_frame(libwebsock_client_state *state, libwebsock_frame *ctl_frame)
{
  libwebsock_frame *ptr = NULL;
  state->control_callback(state, ctl_frame);
  //the idea here is to reset this frame to the state it was in before we received control frame.
  // Control frames can be injected in the midst of a fragmented message.
  // We need to maintain the link to previous frame if present.
  // It should be noted that ctl_frame is still state->current_frame after this function returns.
  // So even though the below refers to ctl_frame, I'm really setting up state->current_frame to continue receiving data on the next go 'round
  ptr = ctl_frame->prev_frame; //This very well may be a NULL pointer, but just in case we preserve it.
  ctl_frame->prev_frame = ptr;
  //should be able to reuse this frame by setting these two members to zero.  Avoid free/malloc of rawdata
  ctl_frame->state = 0;
  ctl_frame->rawdata_idx = 0;
}

void
libwebsock_cleanup_frames(libwebsock_frame *first)
{
  libwebsock_frame *this = NULL;
  libwebsock_frame *next = first;
  while (next != NULL) {
    this = next;
    next = this->next_frame;
    if (this->rawdata != NULL) {
      free(this->rawdata);
    }
    free(this);
  }
}

inline void
libwebsock_frame_act(libwebsock_client_state *state, libwebsock_frame *frame)
{
  switch (frame->opcode) {
    case WS_OPCODE_CLOSE:
    case WS_OPCODE_PING:
    case WS_OPCODE_PONG:
      libwebsock_handle_control_frame(state, frame);
      break;
    case WS_OPCODE_TEXT:
    case WS_OPCODE_BINARY:
    case WS_OPCODE_CONTINUE:
      libwebsock_dispatch_message(state, frame);
      state->current_frame = NULL;
      break;
    default:
      libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
      break;
  }
}

int
libwebsock_read_header(libwebsock_frame *frame)
{
  int i;
  enum WS_FRAME_STATE state;

  state = frame->state;
  switch (state) {
    case sw_start:
      if (frame->rawdata_idx < 2) {
        break;
      }
      frame->state = sw_got_two;
      break;
    case sw_got_two:
      if ((*(frame->rawdata) & 0x70) != 0) { //some reserved bits were set
        return -1;
      }
      if ((*(frame->rawdata + 1) & 0x80) != 0x80) {
        return -1;
      }
      frame->mask_offset = 2;
      frame->fin = (*(frame->rawdata) & 0x80) == 0x80 ? 1 : 0;
      frame->opcode = *(frame->rawdata) & 0xf;
      frame->payload_len_short = *(frame->rawdata + 1) & 0x7f;
      frame->state = sw_got_short_len;
      break;
    case sw_got_short_len:
      switch (frame->payload_len_short) {
        case 126:
          if (frame->rawdata_idx < 4) {
            break;
          }
          frame->mask_offset += 2;
          frame->payload_offset = frame->mask_offset + MASK_LENGTH;
          frame->payload_len = be16toh(*((unsigned short int *)(frame->rawdata+2)));
          frame->state = sw_got_full_len;
          break;
        case 127:
          if (frame->rawdata_idx < 10) {
            break;
          }
          frame->mask_offset += 8;
          frame->payload_offset = frame->mask_offset + MASK_LENGTH;
          frame->payload_len = be64toh(*((unsigned long long *)(frame->rawdata+2)));
          frame->state = sw_got_full_len;
          break;
        default:
          frame->payload_len = frame->payload_len_short;
          frame->payload_offset = frame->mask_offset + MASK_LENGTH;
          frame->state = sw_got_full_len;
          break;
      }
      break;
    case sw_got_full_len:
      if (frame->rawdata_idx < frame->mask_offset + MASK_LENGTH) {
        break;
      }
      for (i = 0; i < MASK_LENGTH; i++) {
        frame->mask[i] = *(frame->rawdata + frame->mask_offset + i) & 0xff;
      }
      frame->state = sw_loaded_mask;
      return 1;
      break;
    case sw_loaded_mask:
      break;
  }
  return 0;
}
