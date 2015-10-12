CXX=clang++
CXXFLAGS=-std=c++14 -stdlib=libc++ -Wall -Wextra -pedantic -fPIC -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2
SANITIZE=-fsanitize=address,undefined
DEBUG=-g -DDEBUG
OPTIMIZE=-O3
LINK=-Wl,-z,relro,-z,now,-z,noexecstack
INCS=-I include
OUTPUT=-shared -o lib/hookffi.so

default: build/hookffi.o
	${CXX} ${CXXFLAGS} ${OPTIMIZE} ${INCS} ${LINK} ${OUTPUT} build/hookffi.o

debug: build/hookffi.o
	${CXX} ${CXXFLAGS} ${DEBUG} ${SANITIZE} ${INCS} ${LINK} ${OUTPUT} build/hookffi.o

vdebug: build/hookffi.o
	${CXX} ${CXXFLAGS} ${DEBUG} ${INCS} ${LINK} ${OUTPUT} build/hookffi.o

build/hookffi.o: src/hookffi.cc
	${CXX} ${CXXFLAGS} ${INCS} -o build/hookffi.o -c src/hookffi.cc

clean:
	rm lib/hookffi.so build/hookffi.o
