#include "helpers.h"

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
    Execute payload in memory.
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
void writeToDisk(void *payload, char *pathToWrite, int size){
    FILE *outfile = fopen(pathToWrite, "w");
    fwrite(payload, sizeof(char), size, outfile);
    fclose(outfile);
}