CXX=clang++
CXXFLAGS=-std=c++14 -stdlib=libc++ -Wall -Wextra -pedantic -fPIC -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2
SANITIZE=-fsanitize=address,undefined
DEBUG=-g -DDEBUG
OPTIMIZE=-O3
LINK=-pie -L ../../lib -L vendor/libuv/.libs/ -Wl,-z,relro,-z,now,-z,noexecstack
INCS=-I include -I ../../include/ -I vendor/libuv/include
OUTPUT=-o shambles

LIBS=-lmnl -lcap -lpthread -Wl,-Bstatic -luv -lshambles -Wl,-Bdynamic

default: build/main.o build/util.o
	${CXX} ${CXXFLAGS} ${OPTIMIZE} ${INCS} ${LINK} ${OUTPUT} build/main.o build/util.o ${LIBS}

debug: build/main.o build/util.o
	${CXX} ${CXXFLAGS} ${DEBUG} ${INCS} ${SANITIZE} ${LINK} ${OUTPUT} build/main.o build/util.o ${LIBS}

vdebug: build/main.o build/util.o
	${CXX} ${CXXFLAGS} ${DEBUG} ${INCS} ${LINK} ${OUTPUT} build/main.o build/util.o ${LIBS}

build/main.o: src/main.cc
	${CXX} ${CXXFLAGS} ${INCS} -o build/main.o -c src/main.cc

build/util.o: src/util.cc
	${CXX} ${CXXFLAGS} ${INCS} -o build/util.o -c src/util.cc

clean:
	rm shambles build/main.o build/util.o
