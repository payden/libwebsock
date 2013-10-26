/*
 * This file is part of libwebsock
 *
 * Copyright (C) 2012-2013 Payden Sutherland
 *
 * libwebsock is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * libwebsock is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwebsock; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef FRAMES_H_
#define FRAMES_H_
#include "types.h"


void libwebsock_new_continuation_frame(libwebsock_client_state *state);
void libwebsock_fail_and_cleanup(libwebsock_client_state *state);
void libwebsock_free_all_frames(libwebsock_client_state *state);
void libwebsock_cleanup_frames(libwebsock_frame *first);
void libwebsock_dump_frame(libwebsock_frame *frame);


#endif /* FRAMES_H_ */
