CXX=clang++
CXXFLAGS=-std=c++14 -stdlib=libc++ -Wall -Wextra -pedantic -fPIC -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2
SANITIZE=-fsanitize=address,undefined
DEBUG=-g -DDEBUG
OPTIMIZE=-O3
LINK=-Wl,-z,relro,-z,now,-z,noexecstack -pie
OUTPUT=-o scan

INCLUDES=-I ./include -I ../../include
LIBS=-lpcap

default: build/scan.o
	${CXX} ${CXXFLAGS} ${OPTIMIZE} ${LINK} ${OUTPUT} build/scan.o ${LIBS}

debug: build/scan.o
	${CXX} ${CXXFLAGS} ${DEBUG} ${SANITIZE} ${LINK} ${OUTPUT} build/scan.o ${LIBS}

vdebug: build/scan.o
	${CXX} ${CXXFLAGS} ${DEBUG} ${LINK} ${OUTPUT} build/scan.o ${LIBS}

build/scan.o: src/scan.cc
	${CXX} ${CXXFLAGS} ${INCLUDES} -o build/scan.o -c src/scan.cc

clean:
	rm scan build/scan.o
