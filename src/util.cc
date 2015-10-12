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

#include "util.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>


uint8_t parse_ipv4(const char* str, uint64_t len) {
  uint8_t digits = 0;
  uint8_t vals[3] = { 0,0,0 };
  uint8_t dots = 0;
  uint16_t seg = 0;
  for (uint64_t i = 0; i < len; i++) {
    char c = str[i];
    if ('0' <= c && c <= '9') {
      vals[digits] = (uint16_t)c ^ 0x30;
      digits++;
      if (digits > 3) {
        return 1;
      }
    } else if (c == '.') {
      if (i+1 == len || dots == 3) {
        return 2;
      }
      if (digits == 1) {
        seg = vals[0];
      } else if (digits == 2) {
        seg = vals[0]*10 + vals[1];
      } else if (digits == 3) {
        seg = vals[0]*100 + vals[1]*10 + vals[2];
      }

      if (seg > 255) {
        return 3;
      }
      digits = 0; seg = 0;
      dots++;
      if (dots > 3) {
        return 4;
      }
    } else {
      return 5;
    }
  }
  if (dots == 3) {
    return 0;
  }
  return 6;
}

char* inet_htoa_r(char* buf, uint32_t haddr) {
  snprintf(buf, 16, "%hhu.%hhu.%hhu.%hhu",
    (uint8_t)((haddr >> 24) & 0xff),
    (uint8_t)((haddr >> 16) & 0xff),
    (uint8_t)((haddr >> 8) & 0xff),
    (uint8_t)(haddr & 0xff)
  );
  return buf;
}

char* inet_ntoa_r(char* buf, uint32_t haddr) {
  snprintf(buf, 16, "%hhu.%hhu.%hhu.%hhu",
    (uint8_t)((haddr) & 0xff),
    (uint8_t)((haddr >> 8) & 0xff),
    (uint8_t)((haddr >> 16) & 0xff),
    (uint8_t)((haddr >> 24) & 0xff)
  );
  return buf;
}

char hdc(uint8_t const _element) {
  if ( 0x20 <= _element && _element <= 0x7e) {
    return _element;
  } else {
    return '.';
  }
}

void hexdump_line(uint8_t const * const _data, uint16_t const off) {
  printf( "%04x  %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx "
          " %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx"
          "  %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c"
          "\n",
      off, _data[0], _data[1], _data[2], _data[3],
      _data[4], _data[5], _data[6], _data[7],
      _data[8], _data[9], _data[10], _data[11],
      _data[12], _data[13], _data[14], _data[15],
      hdc(_data[0]), hdc(_data[1]), hdc(_data[2]), hdc(_data[3]), 
      hdc(_data[4]), hdc(_data[5]), hdc(_data[6]), hdc(_data[7]), 
      hdc(_data[8]), hdc(_data[9]), hdc(_data[10]), hdc(_data[11]), 
      hdc(_data[12]), hdc(_data[13]), hdc(_data[14]), hdc(_data[15]) 
  );
}

void hexdump(uint8_t const * const _data, uint16_t const _data_len) {
  uint16_t modlen = _data_len % 16;
  uint16_t looplen = _data_len - modlen;
  printf("modlen: %hu  looplen: %hu\n", modlen, looplen);
  uint16_t i = 0;
  if (looplen >= 16) {
    for (; i < looplen; i+=16) {
      hexdump_line( &(_data[i]), i);
    }
    if ( modlen == 0 ) {
      return;
    }
  }
  uint8_t rem[16] = {0};
  printf("uint8_t rem[16] = {0};\n");
  memcpy(rem, &(_data[i]), modlen);
  printf("memcpy(rem, &(_data[i]), modlen);\n");
  hexdump_line(rem, i);
  printf("hexdump_line(rem, i);\n");
}

void tcp_state_dump(tcp_state_t const * const _tst) {
  char buf[16];
  printf( "src_ip: %s\n"
                "dst_ip: %s\n"
                "sport: %hu\n"
                "dport: %hu\n",
      inet_ntoa_r(buf, _tst->src_ip),
      inet_ntoa_r(buf, _tst->dst_ip),
      ntohs(_tst->sport), ntohs(_tst->dport)
  );
  printf( "seq: %x\n"
          "ack: %x\n",
      _tst->seq, _tst->ack
  );

  printf("snd_una: %x\n", _tst->snd_una);
  printf("tstamp_ok: %hhx\n", _tst->tstamp_ok);
  printf("sack_ok: %hhx\n", _tst->sack_ok);
  printf("wscale_ok: %hhx\n", _tst->wscale_ok);
  printf("ecn_ok: %hhx\n", _tst->ecn_ok);
  printf("snd_wscale: %hhx\n", _tst->snd_wscale);
  printf("rcv_wscale: %hhx\n", _tst->rcv_wscale);
  printf("snd_wnd: %x\n", _tst->snd_wnd);
  printf("rcv_wnd: %x\n", _tst->rcv_wnd);
  printf("ts_recent: %x\n", _tst->ts_recent);
  printf("ts_val: %x\n", _tst->ts_val);
  printf("mss_clamp: %x\n", _tst->mss_clamp);
}

void pkt_data_dump(pkt_data_t const * const _pdt) {
  char buf1[16];
  char buf2[16];
  printf( "src_addr: %s\n"
                "dst_addr: %s\n"
                "src_port: %hu\n"
                "dst_port: %hu\n",
    inet_ntoa_r(buf1, _pdt->src_addr),
    inet_ntoa_r(buf2, _pdt->dst_addr),
    ntohs(_pdt->src_port), ntohs(_pdt->dst_port)
  );
  printf( "seq: %x\n"
                "ack: %x\n",
    _pdt->seq, _pdt->ack
  );

  hexdump(_pdt->msg, ntohs(_pdt->msg_len));
}

/*
void hook_data_dump(hook_data_t const * const _hdt) {
  char buf[16];
  printf( "outer_addr: %s\n"
          "inner_addr: %s\n"
          "outer_port: %hu\n"
          "innet_port: %hu\n",
      inet_ntoa_r(buf, _hdt->outer_addr),
      inet_ntoa_r(buf, _hdt->inner_addr),
      ntohs(_hdt->outer_port), ntohs(_hdt->inner_port)
  );
}
*/

