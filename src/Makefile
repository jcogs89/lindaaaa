CC=gcc
CFLAGS=-I. -D_GNU_SOURCE -g
BINARIES=detect.o lindaaaa.o helpers.o
TARGET=../build/lindaaaa

lindaaaamake: $(BINARIES)
	$(CC) -o $(TARGET) $(BINARIES) $(FLAGS)

clean:
	rm $(BINARIES)