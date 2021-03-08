#ifndef HELPERS_H
#define HELPERS_H

#include <stdio.h>
#include <unistd.h>
#include <sodium.h>
#include <string.h>
#include "miniz.h"
#include "preferences.h"

#ifdef MINIZ_STATIC
#define MINIZ_STATIC static
#else
#define MINIZ_STATIC
#endif

typedef struct payloadStruct{
    unsigned int uncompressedLength;
    unsigned int encryptedLength;
    unsigned int decryptedLength;
}PayloadStruct;

unsigned char *decrypt(unsigned char *encrypted, unsigned int input_length, unsigned int original_size);
unsigned char *decompress(unsigned char *decrypted, uLong uncomp_len, uLong compressed_len);

int fsize(FILE *fp);
int executePayload(int payload_fd, char **payload_argv, char **payload_envp);
void writeToDisk(void *payload, char *pathToWrite, int size);

unsigned int getUncompLen(unsigned char *payload);
unsigned int getDecryptedLen(unsigned char *payload);
unsigned int getEncLen(unsigned char *payload);
unsigned int getNumPayloads(unsigned char *payload);

char *psswdPadding(char *psswd);

#endif