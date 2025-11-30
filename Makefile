CC=gcc
CFLAGS= -lpcap -lmosquitto

SRC=src/myids.c
OUT=build/myids

all:
	$(CC) -o $(OUT) $(SRC) $(CFLAGS)

clean:
	rm -f build/myids
