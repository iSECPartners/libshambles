/*-
 * Copyright (c) 2015 NCC Group
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef LIBSHAMBLES_UTIL_H_
#define LIBSHAMBLES_UTIL_H_

#include <stdint.h>

#include "shambles.h"
#include "forgery.h"

#ifdef DEBUG
  #define DEBUG_printf(...) fprintf(stderr, __VA_ARGS__)
#else
  #define DEBUG_printf(...) (void)0
#endif

uint8_t parse_ipv4(const char* str, uint64_t len);

/**
* Usage:
*   char buf[16];
*   inet_htoa_r(buf, ntohl(inet_addr("1.2.3.4")));
*/
char* inet_htoa_r(char* buf, uint32_t haddr);


/**
* Usage:
*   char buf[16];
*   inet_ntoa_r(buf, inet_addr("1.2.3.4"));
*/
char* inet_ntoa_r(char* buf, uint32_t haddr);

void hexdump(uint8_t const * const _data, uint16_t const _data_len);
void tcp_state_dump(tcp_state_t const * const _st);
void pkt_data_dump(pkt_data_t const * const _pd);
//void hook_data_dump(hook_data_t const * const _hdt);

#endif
