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

#include "forgery.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <arpa/inet.h>

int const one = 1;
static struct sockaddr_in const ipv4_anywhere = { AF_INET, 0, {inet_addr("127.0.0.1")}, {0} };

int8_t set_forged_sock_opts(int sock) {
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
    perror("set_forged_sock_opts:setsockopt:SOL_SOCKET/SO_REUSEADDR/one");
    return -1;
  }
  return 1;
}

int8_t bind_forged_sock_ipv4_anywhere(int sock) {
  if (bind(sock, (struct sockaddr *)&ipv4_anywhere, sizeof(ipv4_anywhere)) < 0) {
    perror("bind_forged_sock_ipv4_anywhere:bind");
    return -1;
  }
  return 1;
}

int8_t forge_tcp_state(int sock, tcp_state_t* forged_state) {
  if (setsockopt(sock, IPPROTO_TCP, TCP_STATE, forged_state, sizeof(tcp_state_t)) < 0) {
    perror("forge_tcp_state:setsockopt:IPPROTO_TCP/TCP_STATE/forged_state");
    return -1;
  }
  return 1;
}