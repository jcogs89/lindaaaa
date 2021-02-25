#ifndef HELPERS_H
#define HELPERS_H

#include <stdio.h>
#include <unistd.h>
#include <sodium.h>
#include <string.h>
// #include "miniz.h"
// #include "miniz.c"

// #ifdef MINIZ_STATIC
// # define MINIZ_STATIC static
// #else
// # define MINIZ_STATIC
// #endif

// static int decrypt(const char* target_file, const char* source_file, const unsigned char key[crypto_secretbox_KEYBYTES]);
// int decompress(void);

int fsize(FILE *fp);
int executePayload(int payload_fd, char **payload_argv, char **payload_envp);
void writeToDisk(void *payload, char *pathToWrite, int size);

#endif