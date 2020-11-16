#include "detect.h"
#include <elf.h>

//determine if the file is executable using the file's magic numbers
//specifically checks if file is an ELF
//returns 1 if it's executable/ELF and 0 if it isn't
int detect(unsigned char *payload){
    unsigned char elfMagic[4] = {0x7F, 0x45, 0x4C, 0x46};
    
    for(int i = 0; i < 4; i++){      //check the payload's magic bytes
        if (payload[i] != elfMagic[i]){
            printf("Not executable\n");
            return 0;
        }
    }
    printf("It's an ELF\n");
    if (((Elf64_Ehdr *)payload)->e_entry == 0){ //check if there's an entry point
        printf("There's no entry point, considering shared object file\n");
        return 0;
    }
    printf("There's an entry point\nEntry = %lu\n",((Elf64_Ehdr *)payload)->e_entry);
    return 1;
}
