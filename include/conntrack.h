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

#ifndef LIBSHAMBLES_CONNTRACK_H_
#define LIBSHAMBLES_CONNTRACK_H_

#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>

#include <type_traits>

struct ConntrackOption { };
struct ConntrackInjectOption : ConntrackOption { };
struct ConntrackDeleteOption : ConntrackOption { };
struct ConntrackWatOption : ConntrackOption { };

struct Conntrack {
  using Inject = ConntrackInjectOption;
  using Delete = ConntrackDeleteOption;
  using Wat = ConntrackWatOption;
};

const uint32_t timeout = htonl(120);
const size_t mnl_socket_buffer_size = MNL_SOCKET_BUFFER_SIZE;

// ip addresses are struct in_addr (aka uint32_t in network byte order)
// ports are in network byte order
//  typename = std::enable_if<std::is_base_of<T, ConntrackOption>::value, T>

template<
  typename T,
  typename = std::enable_if_t<std::is_base_of<ConntrackOption, T>::value>
>
int32_t conntrack_ipv4_tcp(uint32_t orig_src_addr, uint32_t orig_dst_addr,
                           uint16_t orig_src_port, uint16_t orig_dst_port,
                           uint32_t repl_src_addr, uint32_t repl_dst_addr,
                           uint16_t repl_src_port, uint16_t repl_dst_port) {
  static_assert(
    std::is_same<T, Conntrack::Inject>::value
      || std::is_same<T, Conntrack::Delete>::value,
    "calls to conntrack_ipv4_tcp must use an Inject or Delete parameter");

  struct mnl_socket *sock;
  struct nlmsghdr *hdr;
  struct nfgenmsg *gmsg;

  char* buf = (char*)alloca(mnl_socket_buffer_size);
  memset(buf, 0, mnl_socket_buffer_size);

  sock = mnl_socket_open(NETLINK_NETFILTER);
  if (sock == NULL) {
    perror("mnl_socket_open");
    return -1;
  }

  if (mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0) {
    perror("mnl_socket_bind");
    return -2;
  }

  uint32_t portid = mnl_socket_get_portid(sock);

  hdr = mnl_nlmsg_put_header(buf);

  if (std::is_same<T, Conntrack::Inject>::value) {
    hdr->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8)
                        | 0 /*IPCTNL_MSG_CT_NEW*/;
    hdr->nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
  } else if (std::is_same<T, Conntrack::Delete>::value) {
    hdr->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8)
                        | 2 /*IPCTNL_MSG_CT_DELETE*/;
    hdr->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
  }

  uint32_t seq = time(0);
  hdr->nlmsg_seq = seq;

  gmsg = static_cast<struct nfgenmsg *>(
    mnl_nlmsg_put_extra_header(hdr, sizeof(struct nfgenmsg))
  );
  gmsg->nfgen_family = AF_INET;
  gmsg->version = NFNETLINK_V0;
  gmsg->res_id = 0;

  {
    struct nlattr *nest = mnl_attr_nest_start(hdr, 1 /*CTA_TUPLE_ORIG*/);
    if (nest == nullptr) {
      perror("mnl_attr_nest_start:nfct_build_tuple");
      return -3;
    }

    {
      struct nlattr *nest = mnl_attr_nest_start(hdr, 1 /*CTA_TUPLE_IP*/);
      if (nest == nullptr) {
        perror("mnl_attr_nest_start:CTA_TUPLE_IP");
        return -4;
      }
      mnl_attr_put_u32(hdr, 1 /*CTA_IP_V4_SRC*/, orig_src_addr);
      mnl_attr_put_u32(hdr, 2 /*CTA_IP_V4_DST*/, orig_dst_addr);
      mnl_attr_nest_end(hdr, nest);
    }

    {
      struct nlattr *nest = mnl_attr_nest_start(hdr, 2 /*CTA_TUPLE_PROTO*/);
      if (nest == nullptr) {
        perror("mnl_attr_nest_start:CTA_TUPLE_PROTO");
        return -5;
      }

      mnl_attr_put_u8( hdr, 1 /*CTA_PROTO_NUM*/,      IPPROTO_TCP);
      mnl_attr_put_u16(hdr, 2 /*CTA_PROTO_SRC_PORT*/, orig_src_port);
      mnl_attr_put_u16(hdr, 3 /*CTA_PROTO_DST_PORT*/, orig_dst_port);

      mnl_attr_nest_end(hdr, nest);
    }

    mnl_attr_nest_end(hdr, nest);
  }

  {

    struct nlattr *nest = mnl_attr_nest_start(hdr, 2 /*CTA_TUPLE_REPLY*/);
    if (nest == nullptr) {
      perror("mnl_attr_nest_start:nfct_build_tuple");
      return -6;
    }

    {
      struct nlattr *nest = mnl_attr_nest_start(hdr, 1 /*CTA_TUPLE_IP*/);
      if (nest == nullptr) {
        perror("mnl_attr_nest_start:CTA_TUPLE_IP");
        return -7;
      }
      mnl_attr_put_u32(hdr, 1 /*CTA_IP_V4_SRC*/, repl_src_addr);
      mnl_attr_put_u32(hdr, 2 /*CTA_IP_V4_DST*/, repl_dst_addr);
      mnl_attr_nest_end(hdr, nest);
    }

    {
      struct nlattr *nest = mnl_attr_nest_start(hdr, 2 /*CTA_TUPLE_PROTO*/);
      if (nest == nullptr) {
        perror("mnl_attr_nest_start:CTA_TUPLE_PROTO");
        return -8;
      }

      mnl_attr_put_u8( hdr, 1 /*CTA_PROTO_NUM*/,      IPPROTO_TCP);
      mnl_attr_put_u16(hdr, 2 /*CTA_PROTO_SRC_PORT*/, repl_src_port);
      mnl_attr_put_u16(hdr, 3 /*CTA_PROTO_DST_PORT*/, repl_dst_port);

      mnl_attr_nest_end(hdr, nest);
    }

    mnl_attr_nest_end(hdr, nest);
  }

  if (std::is_same<T, Conntrack::Inject>::value) {
    mnl_attr_put_u32(hdr, 7 /*CTA_TIMEOUT*/, timeout);

    struct nlattr *nest, *nest_proto;
    nest = mnl_attr_nest_start(hdr, 4 /*CTA_PROTOINFO*/);
    if (nest == nullptr) {
      perror("mnl_attr_nest_start:CTA_PROTOINFO");
      return -9;
    }

    nest_proto = mnl_attr_nest_start(hdr, 1 /*CTA_PROTOINFO_TCP*/);
    if (nest_proto == nullptr) {
      perror("mnl_attr_nest_start:CTA_PROTOINFO_TCP");
      return -10;
    }

    mnl_attr_put_u8(hdr, 1 /*CTA_PROTOINFO_TCP_STATE*/,
                         3 /*TCP_CONNTRACK_ESTABLISHED*/);

    mnl_attr_nest_end(hdr, nest_proto);
    mnl_attr_nest_end(hdr, nest);
  }

  if ( mnl_socket_sendto(sock, hdr, hdr->nlmsg_len) == -1 ) {
    perror("mnl_socket_sendto");
    return -11;
  }

  int r = 0;
  if ( (r = mnl_socket_recvfrom(sock, buf, mnl_socket_buffer_size)) == -1 ) {
    perror("mnl_socket_recvfrom");
    return -12;
  }

  while (r > 0) {
    r = mnl_cb_run(buf, r, seq, portid, NULL, NULL);
    if (r == 0) {
      break;
    } else if (r == -1) {
      perror("mnl_cb_run");
      return -12;
    }

    if ( (r = mnl_socket_recvfrom(sock, buf, mnl_socket_buffer_size)) == -1 ) {
      perror("mnl_socket_recvfrom");
      return -13;
    }
  }

  if ( mnl_socket_close(sock) == -1 ) {
    perror("mnl_socket_close");
    //TODO if failure occurs here, may have to do a teardown
    return -14;
  }

  return 1;
}

#endif
