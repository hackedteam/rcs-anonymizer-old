CFLAGS=-Wall
LDFLAGS=-s
LDLIBS=-ldl
LDLIBS+=/usr/lib/libssl.a /usr/lib/libcrypto.a /usr/lib/libz.a

bbproxy: bbproxy.c bbproxy-manager.c bbproxy-proxy.c

default: bbproxy

clean:
	rm -f bbproxy
