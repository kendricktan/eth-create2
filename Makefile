 
CC=gcc
INSTALL=install
prefix=/usr/local
CFLAGS=-Wall -Wextra -pedantic -ggdb -O2 -I.
LDFLAGS=

.PHONY : all test clean 

all: eth-create2

sha3.o: sha3.c
	$(CC) -c $(CFLAGS) -o $@ $<

eth-create2.o : eth-create2.c
	$(CC) -c $(CFLAGS) -o $@ $<

eth-create2: sha3.o eth-create2.o 
	$(CC) -o $@ $^ ${LDFLAGS}

clean:
	-rm -f *.o eth-create2