CC=gcc
CFLAGS=-I. -D_GNU_SOURCE -g -lcurl -lsodium
BINARIES=detect.o lindaaaa.o helpers.o getHTTPS.o
TARGET=../build/lindaaaa

lindaaaamake: $(BINARIES)
	$(CC) -o $(TARGET) $(BINARIES) $(FLAGS)

clean:
	rm $(BINARIES)