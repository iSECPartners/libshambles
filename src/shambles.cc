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

#include "shambles.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>

#include <string.h>
#include <stdio.h>

 #include "util.h"


void swap_pkt_data(pkt_data_t const * const _in, pkt_data_t * const _out) {
  _out->src_addr = _in->dst_addr;
  _out->dst_addr = _in->src_addr;

  _out->src_port = _in->dst_port;
  _out->dst_port = _in->src_port;
  
  _out->seq = _in->ack;
  _out->ack = _in->seq;
}


void swap_pkt_data_inline(pkt_data_t * const _self){
  _self->src_addr = _self->src_addr ^ _self->dst_addr;
  _self->dst_addr = _self->src_addr ^ _self->dst_addr;
  _self->src_addr = _self->src_addr ^ _self->dst_addr;

  _self->src_port = _self->src_port ^ _self->dst_port;
  _self->dst_port = _self->src_port ^ _self->dst_port;
  _self->src_port = _self->src_port ^ _self->dst_port;

  _self->seq = _self->seq ^ _self->ack;
  _self->ack = _self->seq ^ _self->ack;
  _self->seq = _self->seq ^ _self->ack;
}


int8_t addr_in_subnet(uint32_t _addr, uint32_t _inner_addr,
                      uint32_t _netmask) {
  if ( (_addr & _netmask) == (_inner_addr & _netmask) ) {
    return static_cast<int8_t>(true);
  }
  return static_cast<int8_t>(false);
}



ssize_t send_forged_sockets(forged_sockets_t const * const _fst,
                           char const * const _path) {

  struct sockaddr_un saddr;
  int fd = socket(AF_LOCAL, SOCK_STREAM, 0);

  if (fd < 0) {
    perror("send_forged_sockets:socket");
    return -1;
  }

  memset(&saddr, 0, sizeof(saddr));
  strncpy(saddr.sun_path, _path, sizeof(saddr.sun_path)-1);
  //strcpy(saddr.sun_path, _path); //generally cli input, this is faster
                                   //n2s: learn to suppress clang-tidy
  // 107 bytes + 1 NUL (pre-nulled by memset)
  DEBUG_printf("%s\n", saddr.sun_path);
  saddr.sun_family = AF_LOCAL;

  if (connect(fd, reinterpret_cast<struct sockaddr*>(&saddr),
              sizeof(saddr)) < 0) {
    perror("send_forged_sockets:connect");
    return -2;
  }

  struct msghdr msg = {0,0,0,0,0,0,0};
  struct iovec iov[1];
  struct cmsghdr *cmsg = NULL;
  int fds[2] = { _fst->outer_sock, _fst->inner_sock };
  union {
    char buf[CMSG_SPACE(sizeof(fds))];
    struct cmsghdr align;
  } u;
  int *fdptr;

  char data[] = "shambles";

  iov[0].iov_base = data;
  iov[0].iov_len = sizeof(data);

  msg.msg_control = u.buf;
  msg.msg_controllen = sizeof(u.buf);
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;

  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int) * 2);
  fdptr = (int *) CMSG_DATA(cmsg);
  memcpy(fdptr, fds, sizeof(int) * 2);

  return sendmsg(fd, &msg, 0);
}

ssize_t send_forged_sockets2(int fd, forged_sockets_t const * const _fst) {

  struct msghdr msg = {0,0,0,0,0,0,0};
  struct iovec iov[1];
  struct cmsghdr *cmsg = NULL;
  int fds[2] = { _fst->outer_sock, _fst->inner_sock };
  union {
    char buf[CMSG_SPACE(sizeof(fds))];
    struct cmsghdr align;
  } u;
  int *fdptr;

  char data[] = "shambles";

  iov[0].iov_base = data;
  iov[0].iov_len = sizeof(data);

  msg.msg_control = u.buf;
  msg.msg_controllen = sizeof(u.buf);
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;

  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int) * 2);
  fdptr = (int *) CMSG_DATA(cmsg);
  memcpy(fdptr, fds, sizeof(int) * 2);

  return sendmsg(fd, &msg, 0);
}