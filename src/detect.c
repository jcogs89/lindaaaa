#include "detect.h"

//determine if the file is executable using the file's magic numbers
//specifically checks if file is an ELF
//returns 1 if it's executable/ELF and 0 if it isn't
int detect(unsigned char *payload){
    unsigned char elfMagic[4] = {0x7F, 0x45, 0x4C, 0x46};
    
    for(int i = 0; i < 4; i++){      //check the payload's magic bytes
        if (payload[i] != elfMagic[i]){
            printf("not executable\n");
            return 0;
        }
    }
    printf("It's executable\n");
    return 1;
}
