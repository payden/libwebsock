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

#ifndef DEFAULT_CALLBACKS_H_
#define DEFAULT_CALLBACKS_H_

#include "types.h"

int libwebsock_default_onclose_callback(libwebsock_client_state *state);
int libwebsock_default_onopen_callback(libwebsock_client_state *state);
int libwebsock_default_onmessage_callback(libwebsock_client_state *state, libwebsock_message *msg);
int libwebsock_default_control_callback(libwebsock_client_state *state, libwebsock_frame *ctl_frame);


#endif /* DEFAULT_CALLBACKS_H_ */
