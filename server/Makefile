CFLAGS=-Wall -pedantic -g -DDEBUG -I../common

all: ntunnel
	
ntunnel: connection.o cfg.o ntunnel.o ../common/unix.o ../common/rsa.o ../common/ini.o ../common/blowfish.o
	cc connection.o cfg.o ntunnel.o ../common/unix.o ../common/rsa.o ../common/ini.o ../common/blowfish.o -o ntunnel -lcrypto

clean:
	rm -f connection.o cfg.o ntunnel.o ntunnel

connection.o: connection.c cfg.h ../common/unix.h ../common/rsa.h ../common/blowfish.h ../common/rsa.h
	cc -c connection.c $(CFLAGS)

ntunnel.o: ntunnel.c connection.h cfg.h ../common/unix.h
	cc -c ntunnel.c $(CFLAGS)

cfg.o: cfg.c cfg.h ../common/ini.h 
	cc -c cfg.c $(CFLAGS)

