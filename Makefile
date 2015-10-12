CXX=clang++
CXXFLAGS=-std=c++14 -stdlib=libc++ -Wall -Wextra -pedantic -fPIC -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2
SANITIZE=-fsanitize=address,undefined
DEBUG=-g -DDEBUG
OPTIMIZE=-O2
INCS=-I include -I vendor -I vendor/forge_socket
LINK=-Wl,-z,relro,-z,now,-z,noexecstack
OUTPUT=-shared -o lib/libshambles.so


default: build/shambles.o build/shambles_intercept.o build/forgery.o build/util.o
	${CXX} ${CXXFLAGS} ${OPTIMIZE} ${LINK} ${OUTPUT} ${INCS} build/shambles.o build/shambles_intercept.o build/forgery.o build/util.o
	ar rcs lib/libshambles.a build/shambles.o build/shambles_intercept.o build/forgery.o build/util.o

debug: build/shambles.o build/shambles_intercept.o build/forgery.o build/util.o
	${CXX} ${CXXFLAGS} ${DEBUG} ${SANITIZE} ${LINK} ${OUTPUT} ${INCS} build/shambles.o build/shambles_intercept.o build/forgery.o  build/util.o
	ar rcs lib/libshambles.a build/shambles.o build/shambles_intercept.o build/forgery.o  build/util.o

vdebug: build/shambles.o build/shambles_intercept.o build/forgery.o build/util.o
	${CXX} ${CXXFLAGS} ${DEBUG} ${LINK} ${OUTPUT} ${INCS} build/shambles.o build/shambles_intercept.o build/forgery.o  build/util.o
	ar rcs lib/libshambles.a build/shambles.o build/shambles_intercept.o build/forgery.o  build/util.o

build/shambles.o: src/shambles.cc
	${CXX} ${CXXFLAGS} ${INCS} -o build/shambles.o -c src/shambles.cc

build/shambles_intercept.o: src/shambles_intercept.cc
	${CXX} ${CXXFLAGS} ${INCS} -o build/shambles_intercept.o -c src/shambles_intercept.cc

build/forgery.o: src/forgery.cc
	${CXX} ${CXXFLAGS} ${INCS} -o build/forgery.o -c src/forgery.cc

build/util.o: src/util.cc
	${CXX} ${CXXFLAGS} ${INCS} -o build/util.o -c src/util.cc

clean:
	rm lib/libshambles.so lib/libshambles.a build/*.o
