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

bool is_numeric(const std::string& s) {
    return !s.empty() && std::find_if(
        s.begin(), 
        s.end(),
        [](char c) {
          return !std::isdigit(c);
        }) == s.end();
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

