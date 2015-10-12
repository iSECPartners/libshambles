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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <pcap.h>

#include "conntrack.h"
#include "forgery.h"
#include "util.h"

constexpr static char const dnat[] = "iptables -t nat -%c PREROUTING -m state --state INVALID,NEW,RELATED,ESTABLISHED -p tcp -s %s --sport %hu -d %s --dport %hu -j DNAT --to-destination %s:%hu";
constexpr static uint16_t dnat_size = sizeof(dnat)    - 1                                                                     + 14         + 2  + 14         + 2                        + 14 + 2;


constexpr static char const snat[] = "iptables -t nat -%c POSTROUTING -m state --state INVALID,NEW,RELATED,ESTABLISHED -p tcp -s %s --sport %hu -d %s --dport %hu -j SNAT --to-source %s:%hu";
constexpr static uint16_t snat_size = sizeof(snat)    - 1                                                                      + 14         + 2  + 14         + 2                   + 14 + 2;

//constexpr static char const conntrackD[] = "conntrack -D --orig-src %s --orig-dst %s -p tcp --orig-port-src %hu --orig-port-dst %hu --reply-port-src %hu --reply-port-dst %hu --reply-src %s --reply-dst %s";
//constexpr static uint16_t conntrackD_size = sizeof(conntrackD)    + 13          + 13                        + 2                 + 2                  + 2                  + 2           + 13           + 13;

//constexpr static char const conntrackI[] = "conntrack -I --orig-src %s --orig-dst %s -p tcp --orig-port-src %hu --orig-port-dst %hu --reply-port-src %hu --reply-port-dst %hu --reply-src %s --reply-dst %s --timeout 60 --state ESTABLISHED";
//constexpr static uint16_t conntrackI_size = sizeof(conntrackI)    + 13          + 13                        + 2                 + 2                  + 2                  + 2           + 13           + 13;



int8_t intercept(forged_sockets_t* _out, pkt_data_t const * const _pd,
                 uint32_t const _outer_addr, uint32_t const _inner_addr) {

  DEBUG_printf("%s\n", __func__);
  #ifdef DEBUG
  pkt_data_dump(_pd);
  #endif

  char inner_addr_str[16] = {0};
  inet_ntoa_r(inner_addr_str, _inner_addr);

  char outer_addr_str[16] = {0};
  inet_ntoa_r(outer_addr_str, _outer_addr);


  char dst_addr[16] = {0};
  inet_ntoa_r(dst_addr, _pd->dst_addr);

  char src_addr[16] = {0};
  inet_ntoa_r(src_addr, _pd->src_addr);


  DEBUG_printf("Deleting old conntrack entry.");
  int32_t delret = conntrack_ipv4_tcp<Conntrack::Delete>(
      _pd->src_addr, _pd->dst_addr,
      _pd->src_port, _pd->dst_port,
      _pd->dst_port, _pd->src_port,
      _pd->dst_addr, _outer_addr
  );
  if (delret != 1) {
    printf("delret: %d\n", delret);
    return -1;
  }


  DEBUG_printf("Injecting new conntrack entries.");
  int32_t injret = conntrack_ipv4_tcp<Conntrack::Inject>(
      _outer_addr, _pd->dst_addr,
      _pd->src_port, _pd->dst_port,
      _pd->dst_addr, _outer_addr,
      _pd->dst_port, _pd->src_port
  );
  if (injret != 1) {
    printf("injret: %d\n", injret);
    return -2;
  }


  char dnat_command[dnat_size] = {0};
  snprintf(dnat_command, dnat_size, dnat,
    'A', src_addr, ntohs(_pd->src_port), dst_addr, ntohs(_pd->dst_port),
    inner_addr_str, ntohs(_pd->dst_port)
  );
  DEBUG_printf("# %s\n", dnat_command);
  system(dnat_command);


  char snat_command[snat_size] = {0};
  snprintf(snat_command, snat_size, snat,
    'A', inner_addr_str, ntohs(_pd->dst_port), src_addr, ntohs(_pd->src_port),
    dst_addr, ntohs(_pd->dst_port)
  );
  DEBUG_printf("# %s\n", snat_command);
  system(snat_command);


  struct tcp_state *fake_server = (tcp_state_t *)calloc(1, sizeof(tcp_state_t));
  if (fake_server == nullptr) {
    return -3;
  }
  struct tcp_state *fake_client = (tcp_state_t *)calloc(1, sizeof(tcp_state_t));
  if (fake_client == nullptr) {
    free(fake_server);
    return -4;
  }
  

  int client_sock = socket(AF_INET, SOCK_FORGE, 0);
  if (client_sock == -1) {
    perror("intercept:socket->client_sock");
    free(fake_server);
    free(fake_client);
    return -5;
  }
  int server_sock = socket(AF_INET, SOCK_FORGE, 0);
  if (server_sock == -1) {
    perror("intercept:socket->server_sock");
    close(client_sock);
    free(fake_server);
    free(fake_client);
    return -6;
  }

  if (set_forged_sock_opts(client_sock) != 1) {
    close(client_sock);
    close(server_sock);
    free(fake_server);
    free(fake_client);
    return -7;
  }
  if (set_forged_sock_opts(server_sock) != 1) {
    close(client_sock);
    close(server_sock);
    free(fake_server);
    free(fake_client);
    return -8;
  }

  if (bind_forged_sock_ipv4_anywhere(client_sock) != 1) {
    close(client_sock);
    close(server_sock);
    free(fake_server);
    free(fake_client);
    return -9;
  }
  if (bind_forged_sock_ipv4_anywhere(server_sock) != 1) {
    close(client_sock);
    close(server_sock);
    free(fake_server);
    free(fake_client);
    return -10;
  }

  fake_client->src_ip = _outer_addr;
  fake_client->dst_ip = _pd->dst_addr;
  fake_client->sport = _pd->src_port;
  fake_client->dport = _pd->dst_port;
  fake_client->seq = ntohl(_pd->seq);
  fake_client->ack = ntohl(_pd->ack);
  fake_client->snd_una = ntohl(_pd->seq);
  fake_client->snd_wnd = 0x1000;
  fake_client->rcv_wnd = 0x1000;


  fake_server->src_ip = _inner_addr;
  fake_server->dst_ip = _pd->src_addr;
  fake_server->sport = _pd->dst_port;
  fake_server->dport = _pd->src_port;
  fake_server->seq = ntohl(_pd->ack);
  fake_server->ack = ntohl(_pd->seq);
  fake_server->snd_una = ntohl(_pd->ack);
  fake_server->snd_wnd = 0x1000;
  fake_server->rcv_wnd = 0x1000;


  if (forge_tcp_state(client_sock, fake_server) != 1) {
    close(client_sock);
    close(server_sock);
    free(fake_server);
    free(fake_client);
    return -11;
  }
  if (forge_tcp_state(server_sock, fake_client) != 1) {
    close(client_sock);
    close(server_sock);
    free(fake_server);
    free(fake_client);
    return -12;
  }


  _out->outer_sock = server_sock;
  _out->inner_sock = client_sock;


  free(fake_server);
  free(fake_client);
  return 1;
}


int8_t intercept_teardown(pkt_data_t const * const _pd,
                          uint32_t const _outer_addr,
                          uint32_t const _inner_addr) {
  DEBUG_printf("%s\n", __func__);
  
  char inner_addr_str[16] = {0};
  inet_ntoa_r(inner_addr_str, _inner_addr);

  char outer_addr_str[16] = {0};
  inet_ntoa_r(outer_addr_str, _outer_addr);


  char dst_addr[16] = {0};
  inet_ntoa_r(dst_addr, _pd->dst_addr);

  char src_addr[16] = {0};
  inet_ntoa_r(src_addr, _pd->src_addr);

  char dnat_command[dnat_size] = {0};
  snprintf(dnat_command, dnat_size, dnat,
    'D', src_addr, ntohs(_pd->src_port), dst_addr, ntohs(_pd->dst_port),
    inner_addr_str, ntohs(_pd->dst_port)
  );
  DEBUG_printf("# %s\n", dnat_command);
  system(dnat_command);

  char snat_command[snat_size] = {0};
  snprintf(snat_command, snat_size, snat,
    'D', inner_addr_str, ntohs(_pd->dst_port), src_addr, ntohs(_pd->src_port),
    dst_addr, ntohs(_pd->dst_port)
  );
  DEBUG_printf("# %s\n", snat_command);
  system(snat_command);
  
  return 0;
}


