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

#ifndef UTIL_H_
#define UTIL_H_
#include <stdint.h>

int validate_utf8_sequence(uint8_t *s);
uint16_t lws_htobe16(uint16_t x);
uint16_t lws_be16toh(uint16_t x);
uint64_t lws_htobe64(uint64_t x);
uint64_t lws_be64toh(uint64_t x);

#endif /* UTIL_H_ */
