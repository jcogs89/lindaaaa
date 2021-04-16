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
    char *killCode = "\x06\x79\x69\x69\x0d\xf3\xa5\x4d\xc9\xd9\x38\x35\xa8\xc6\x32\x22";
    unsigned char hash[MD5_DIGEST_LENGTH];

    MD5(payload, 64, hash);
    for (int i = 0; i < 16; i++)
    {
        if (hash[i] != killCode[i])
        {
            return 0;
        }
    }
    return 1;
}