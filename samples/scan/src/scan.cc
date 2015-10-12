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

typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;
#define EBUF_LEN 160

#include <string.h>
#include <errno.h>
#include <unistd.h>


#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>


#include <string>
#include <regex>

#include <shambles.h>

#ifdef DEBUG
  #define DEBUG_printf(...) fprintf(stderr, __VA_ARGS__)
#else
  #define DEBUG_printf(...) (void)0
#endif

char ebuf[EBUF_LEN] = {0};
int client_sock = 0;
int r = 0;

std::regex regex;

const uint8_t* strnstrn(const uint8_t* haystack, uint32_t hn, const uint8_t* needle, uint32_t nn) {
  for ( uint32_t i(0); i < hn; i++ ) {
    if ( memcmp(haystack+i, needle, nn) == 0 ) {
      return haystack+i;
    }

    if ( (i + nn) == hn) {
      break;
    }
  }
  return nullptr;
}

pkt_data_t pdt = {0,0, 0,0, 0,0, 0,nullptr};


void intercept(struct pkt_data* pb) {



  r = send(client_sock, pb, 22, 0);
  if( r < 0 ) {
    strerror_r(errno, ebuf, sizeof(ebuf));
    fprintf(stderr, "client_sock:send => %s\n", ebuf);
    exit(1);
  }

  r = send(client_sock, pb->msg, pb->msg_len, 0);
  if( r < 0 ) {
    strerror_r(errno, ebuf, sizeof(ebuf));
    fprintf(stderr, "client_sock:send => %s\n", ebuf);
    exit(1);
  }

  close(client_sock);


}


bool tcp_handler(uint32_t rsize, const uint8_t* bytes) {
  if ( rsize < sizeof(tcphdr) ) {
    return false;
  }
  DEBUG_printf("--->TCP!\n");
  tcphdr* hdr = (tcphdr*)bytes;
  uint8_t hdr_size = (hdr->th_off*4);
  if (rsize < hdr_size) {
    return false;
  }

  const uint8_t* payload = bytes + hdr_size;
  uint32_t payload_size = rsize - hdr_size;

//  uint8_t query[] = "HELLO WORLD!";
//  const uint8_t* match = strnstrn(payload, rsize, query, strlen((char*)query));
//  if (match != nullptr) {
  if(std::regex_search(std::string((char*)payload, payload_size), regex)) {
    pdt.src_port = hdr->th_sport;
    pdt.dst_port = hdr->th_dport;
    pdt.seq = htonl(ntohl(hdr->th_seq) + payload_size);
    pdt.ack = hdr->th_ack;
    pdt.msg_len = htons(payload_size);
    pdt.msg = (uint8_t*)malloc(payload_size);
    if (pdt.msg != nullptr) {
      memcpy(pdt.msg, payload, payload_size);
    }
    return true;
  }

  return false;
}

bool ip_handler(uint32_t rsize, const uint8_t* bytes) {
  if ( rsize < sizeof(ip) ) {
    return false;
  }
  DEBUG_printf("->IP!\n");

  ip* hdr4 = (ip*)bytes;
  uint8_t version = hdr4->ip_v;

  if (version == 4) {
    uint8_t ihl = hdr4->ip_hl;
    if ( rsize < ihl ) {
      return false;
    }

    uint8_t hdr4_size = ihl*4;
    const uint8_t* payload = bytes + hdr4_size;
    switch(hdr4->ip_p) {
      case IPPROTO_TCP:
         if ( tcp_handler(rsize - hdr4_size, payload) ) {
           pdt.src_addr = hdr4->ip_src.s_addr;
           pdt.dst_addr = hdr4->ip_dst.s_addr;
           return true;
         }
         return false;
        break;
      default:
        return false;
    }



  } else {
    if ( rsize < sizeof(ip6_hdr) ) {
      return false;
    }
    ip6_hdr* hdr6 = (ip6_hdr*)bytes;
    (void)hdr6;
    // not handling ipv6 right now
    return false;
  }
  return false;
}

void eth_handler(uint8_t* user, const struct pcap_pkthdr* pkthdr, const uint8_t* bytes) {
  (void)user;
  DEBUG_printf("GOT ONE!\n");
  uint32_t capturedSize = pkthdr->caplen;
  ether_header* hdr = (ether_header*)bytes;


  if (capturedSize < sizeof(ether_header)) {
    return;
  } else if (ntohs(hdr->ether_type) == ETHERTYPE_IP) {
    if ( ip_handler(capturedSize - sizeof(ether_header), bytes + sizeof(ether_header)) ) {
      DEBUG_printf("ZA WARUDO!\n");
      intercept(&pdt);
      free(pdt.msg);
      exit(0);
    }
  } else {
    DEBUG_printf("WAT?\n");
  }

  return;
}

int main(int argc, char const *argv[]) {

  if (argc != 6) {
    fprintf(stderr, "Usage: %s <device> <bpf filter> <regex signature> "
                    "<interceptor host> <interceptor port>\n", argv[0]);
    return -1;
  }

  pcap_t *handle;   /* Session handle */
  char const* dev = argv[1];    /* Device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
  struct bpf_program fp;    /* The compiled filter expression */
  char const* filter_exp = argv[2];  /* The filter expression */
  bpf_u_int32 mask;   /* The netmask of our sniffing device */
  bpf_u_int32 net;    /* The IP of our sniffing device */

  try {
    regex = std::regex(argv[3]);
  } catch (const std::regex_error& e) {
     fprintf(stderr, "Invalid regular expression: %s\nError: %s\n", argv[3], e.what());
     return -1;
  }
  struct sockaddr_in remote; memset(&remote, 0, sizeof(remote));
  remote.sin_family = AF_INET;
  remote.sin_port = htons(atoi(argv[5]));


  r = inet_pton(AF_INET, argv[4], &remote.sin_addr);
  if (r != 1) {
    if (r == 0) {
      fprintf(stderr, "remote:inet_pton => %s\n", "Invalid network address string.");
      return -1;
    } else {
      strerror_r(errno, ebuf, sizeof(ebuf));
      fprintf(stderr, "remote:inet_pton => %s\n", ebuf);
      return -1;
    }
  }

  client_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (client_sock < 0) {
    strerror_r(errno, ebuf, sizeof(ebuf));
    fprintf(stderr, "client_sock:socket => %s\n", ebuf);
    return -1;
  }

  r = connect(client_sock, (struct sockaddr*) &remote, sizeof(remote));
  if (r != 0) {
    strerror_r(errno, ebuf, sizeof(ebuf));
    fprintf(stderr, "client_sock:connect => %s\n", ebuf);
    free(pdt.msg);
    return -1;
  }



  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Can't get netmask for device %s\n", dev);
    net = 0;
    mask = 0;
  }

  puts("Starting capture...");
  handle = pcap_open_live(dev, 1000, 0, 1, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return -2;
  }
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return -2;
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return -2;
  }

  int loopret = pcap_loop(handle, 0, eth_handler, nullptr);
  if (loopret == -1) {
    fprintf(stderr, "Something bad happened.\n");
    return -3;
  } else if (loopret == -2) {
    fprintf(stderr, "Bail OUT\n");
    return -3;
  }

  return 0;
}
