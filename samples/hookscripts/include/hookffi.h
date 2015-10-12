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

#ifndef LIBINTERCEPT_HOOKFFI_HOOKFFI_H_
#define LIBINTERCEPT_HOOKFFI_HOOKFFI_H_


typedef struct uds_data {
  int outer_sock;
  int inner_sock;
  int uds_client;
} uds_data_t;

typedef int hook_cb(uds_data_t* _data);

#ifdef DEBUG
  #define DEBUG_printf(...) fprintf(stderr, __VA_ARGS__)
#else
  #define DEBUG_printf(...) (void)0
#endif

extern "C" {

int setup_server(char const * const _path);
int8_t allow_user(char const * const _path, char const * const _user);
int8_t register_hook(hook_cb* _hcb);
int8_t start(int _fd, uds_data_t* _data);
int teardown(uds_data_t* _data);

int close_forged_sockets_early(uds_data_t* _data);

}

#endif