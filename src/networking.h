#ifndef NETWORKING_H
#define NETWORKING_H

#include <stdio.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct MemoryStruct
{
  char *memory;
  size_t size;
};

struct MemoryStruct getHTTPS();
struct MemoryStruct beacon();

#endif