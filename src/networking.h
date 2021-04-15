#ifndef NETWORKING_H
#define NETWORKING_H

#include <stdio.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

struct MemoryStruct
{
  char *memory;
  size_t size;
};

struct MemoryStruct getHTTPS(char *URL);
struct MemoryStruct beacon(char *URL, char initial);

#endif