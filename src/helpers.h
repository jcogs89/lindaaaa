#ifndef HELPERS_H
#define HELPERS_H

#include <stdio.h>
#include <unistd.h>
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include "miniz.h"
#include "preferences.h"

#ifdef MINIZ_STATIC
#define MINIZ_STATIC static
#else
#define MINIZ_STATIC
#endif

/**
 * @brief Holds all supplemental data needed for deployment of payload.
 * @param uncompressedLength: Length of payload when uncompressed.
 * @param encryptedLength: Length of payload when encrypted.
 * @param decryptedLength: Length of payload when decrypted.
 * @param flags: 32 bit wide field of boolean flags for payload deployment.
 * @param argv: Payload argv.
 * @param envp: Payload envp.
 */
typedef struct payloadStruct
{
    unsigned int uncompressedLength;
    unsigned int encryptedLength;
    unsigned int decryptedLength;
    unsigned int flags;
    char **argv;
    char **envp;
} PayloadStruct;

unsigned char *decrypt(unsigned char *encrypted, unsigned int input_length, unsigned int original_size, unsigned char *key);
unsigned char *decompress(unsigned char *decrypted, uLong uncomp_len, uLong compressed_len);

int fsize(FILE *fp);
int executePayload(int payload_fd, char **payload_argv, char **payload_envp);
void writeToDisk(void *payload, char *pathToWrite, int size);

unsigned int extractInt(unsigned char *payload);

unsigned char *psswdPadding();
char *formatURL(char *payload, char *uid);
char *genUID();
size_t countPayloads(char *payloads);
size_t countLines(char *payloads);
char **parsePayloads(char *payloads, size_t numPayloads, char *sep);

PayloadStruct *parseMeta(unsigned char **payloadOffset);
void extractStrArr(unsigned int numStrs, char ***dest, unsigned char **payloadOffset, char save);

#endif