CC=gcc
CFLAGS=-I. -D_GNU_SOURCE -g -lsodium -lcrypto -lcurl
BINARIES=detect.o lindaaaa.o helpers.o networking.o miniz.o
TARGET=../build/lindaaaa

lindaaaamake: $(BINARIES)
	$(CC) -o $(TARGET) $(BINARIES) $(CFLAGS)

clean:
	rm $(BINARIES)