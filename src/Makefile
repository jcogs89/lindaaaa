CC=gcc
CFLAGS=-I. -D_GNU_SOURCE -g -lsodium -lcurl
BINARIES=detect.o lindaaaa.o helpers.o getHTTPS.o
TARGET=../build/lindaaaa

lindaaaamake: $(BINARIES)
	$(CC) -o $(TARGET) $(BINARIES) $(CFLAGS)

clean:
	rm $(BINARIES)