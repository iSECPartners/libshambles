'''
 Copyright (c) 2015 NCC Group
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.
'''

require 'ffi'
require 'socket'

module Hookffi
  extend FFI::Library
  ffi_lib "./lib/hookffi.so"
  class UdsData < FFI::Struct
    layout :outer_sock, :int,
           :inner_sock, :int,
           :uds_client, :int
  end

  callback :hook, [UdsData.by_ref], :int

  attach_function :setup_server, [:string], :int
  attach_function :allow_user, [:string, :string], :uchar
  attach_function :register_native_hook, :register_hook, [:hook], :uchar
  attach_function :start, [:int, UdsData.by_ref], :uchar
  attach_function :teardown, [UdsData.by_ref], :int
  attach_function :close_forged_sockets_early, [UdsData.by_ref], :int
end

Hookffi::HookCallback = FFI::Function.new(:int, [Hookffi::UdsData.by_ref], :blocking => true) do |uds|
  outer_sock = Socket.for_fd(uds[:outer_sock])
  inner_sock = Socket.for_fd(uds[:inner_sock])

  custom_hook(outer_sock, inner_sock)
  Hookffi.teardown(uds)
  0
end





def custom_hook(outer_sock, inner_sock)
  puts "Hooked from Ruby!"

  outer_sock.send "YO SERVER, THIS IS RUBY!\n", 0
  inner_sock.send "YO CLIENT, THIS IS RUBY!\n", 0

  puts "Server says: " + outer_sock.recv(1024)
  puts "Client says: " + inner_sock.recv(1024)
end





if __FILE__ == $PROGRAM_NAME
  if ARGV.length != 2
    puts "Usage: python hook.py <unix domain socket path> " +
         "<user to expose access>"
    -1
  end
  path = ARGV[0]
  uname = ARGV[1]

  uds_server_sock = Hookffi.setup_server path
  Hookffi.allow_user path, uname

  Hookffi.register_native_hook Hookffi::HookCallback

  data = Hookffi::UdsData.new
  Hookffi.start uds_server_sock, data
end




