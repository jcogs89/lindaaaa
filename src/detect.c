/**
 * Functions to detect executable files and the killFile.
 * 
 * Authors: Robert Weiner, Elitania Venturella
 */

#include "detect.h"

/**
 * @brief Determine if the file is executable using the file's magic numbers and if it has an ELF entry point.
 * @param payload: Payload file to check if executable.
 * @retval 1 if it's executable/ELF, 0 if it isn't.
 */
int detect(unsigned char *payload)
{
    unsigned char elfMagic[4] = {0x7F, 0x45, 0x4C, 0x46};

    for (int i = 0; i < 4; i++)
    { //check the payload's magic bytes
        if (payload[i] != elfMagic[i])
        {
            return 0;
        }
    }
    if (((Elf64_Ehdr *)payload)->e_entry == 0)
    { //check if there's an entry point
        return 0;
    }
    return 1;
}

/**
 * @brief Checks if the payload is the killFile.
 * @param payload: Payload file to check.
 * @retval 1 if the file is the killFile, 0 if not
 */
int checkKill(unsigned char *payload)
{
    unsigned char *killCode = "\x8b\x95\x2c\xae\xc6\xeb\x3b\x43\xae\x86\x2b\xd8\xbf\x01\x22\x94\x17\xcb\x6d\x42\x03\x32\x23\x0b\x1a\x05\x7c\x52\x58\x3b\x31\xf3";
    unsigned char hash[crypto_generichash_BYTES];

    crypto_generichash(hash, 32, payload, 64, NULL, 0);
    for (int i = 0; i < 32; i++)
    {
        if (hash[i] != killCode[i])
        {
            return 0;
        }
    }
    return 1;
}