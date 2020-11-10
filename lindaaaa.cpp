#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

//#include <decompress.h>
//#include <decrypt.h>
//#include <execute.h>
//#include <networking.h>


int main(int argc, char **argv){
    void *payload;
    void *decrypted;
    void *decompressed;

    while(receive(payload) != 0){
        puts("BAD SHIT YO");
        sleep(1);
    }

    decrypt(payload, decrypted);
    decompress(decrypted, decompressed);
    execute(decrypted);


    return 0;
}