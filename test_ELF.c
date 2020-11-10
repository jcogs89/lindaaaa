#include <stdio.h>
#include <stdlib.h>

void main(int argc, char **argv){
    FILE *outfile = fopen("./test_out.txt", "w");
    if(argc == 2){
        fputs(argv[1], outfile);
    } else {
        fputs("ERROR", outfile);
    }
}