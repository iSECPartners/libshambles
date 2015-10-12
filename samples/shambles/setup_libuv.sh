#!/bin/sh

cd vendor
git clone https://github.com/libuv/libuv.git
cd libuv
./autogen.sh
./configure CFLAGS="-fPIC -fPIE -fstack-protector-all -D_FORTIFY_SOURCE=2" LDFLAGS="-Wl,-z,relro,-z,now,-z,noexecstack -pie"
make
