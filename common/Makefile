CFLAGS=-Wall -pedantic -g -DDEBUG

all: blowfish.o unix.o rsa.o ini.o
	
clean:
	rm -f blowfish.o unix.o rsa.o ini.o

blowfish.o: blowfish.c blowfish.h
	cc -c blowfish.c $(CFLAGS)

unix.o: unix.c unix.h
	cc -c unix.c $(CFLAGS)
	
rsa.o: rsa.c rsa.h
	cc -c rsa.c $(CFLAGS)
	
ini.o: ini.c ini.h 
	cc -c ini.c $(CFLAGS)

