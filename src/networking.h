#ifndef NETWORKING_H
#define NETWORKING_H

#include <stdio.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

struct MemoryStruct {
  char *memory;
  size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
struct MemoryStruct getHTTPS(char *url);


#endif