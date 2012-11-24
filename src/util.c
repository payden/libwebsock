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

#include "websock.h"

#define UTF8_ACCEPT 0
#define UTF8_REJECT 1

int
validate_utf8_sequence(uint8_t *s)
{
  uint32_t codepoint;
  uint32_t state = 0;

  for(; *s; ++s) {
    decode(&state, &codepoint, *s);
  }


  return state == UTF8_ACCEPT;
}
