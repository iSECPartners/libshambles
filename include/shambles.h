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

#ifndef LIBSHAMBLES_SHAMBLES_H_
#define LIBSHAMBLES_SHAMBLES_H_

#include <stdlib.h>
#include <stdint.h>

extern "C" {

typedef struct __attribute__((__packed__)) pkt_data {
  uint32_t src_addr;
  uint32_t dst_addr;

  uint16_t src_port;
  uint16_t dst_port;

  uint32_t seq;
  uint32_t ack;

  uint16_t msg_len;
  uint8_t* msg;
} pkt_data_t;

typedef struct forged_sockets {
  int outer_sock; // socket for outside host communication
  int inner_sock; // socket for inside host communication
} forged_sockets_t;

void swap_pkt_data(pkt_data_t const * const _in, pkt_data_t * const _out);
void swap_pkt_data_inline(pkt_data_t * const _self);

int8_t addr_in_subnet(uint32_t _addr, uint32_t _inner_addr, uint32_t _netmask);

int8_t intercept(forged_sockets_t* _out, pkt_data_t const * const _pd,
                 uint32_t const _outer_addr, uint32_t const _inner_addr);

int8_t intercept_teardown(pkt_data_t const * const _pd,
                          uint32_t const _outer_addr,
                          uint32_t const _inner_addr);

int8_t addr_in_subnet(uint32_t _addr, uint32_t _inner_addr,
                      uint32_t _netmask);

ssize_t send_forged_sockets(forged_sockets_t const * const _fst,
                           char const * const _path);

ssize_t send_forged_sockets2(int fd, forged_sockets_t const * const _fst);

}

#endif
