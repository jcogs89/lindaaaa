#include "helpers.h"

/*
    Get size in bytes of given file
*/
int fsize(FILE *fp)
{
    int prev = ftell(fp);
    fseek(fp, 0L, SEEK_END);
    int sz = ftell(fp);
    fseek(fp, prev, SEEK_SET); //go back to where we were
    return sz;
}

/*
    Execute payload in memory.
    Return 1 on success, 0 on failure.
*/
int executePayload(int payload_fd, char **payload_argv, char **payload_envp)
{
    if (fexecve(payload_fd, (char *const *)payload_argv, (char *const *)payload_envp) == -1)
    { // execute payload
        puts("fexecve() failed");
        return 0;
    }
    return 1;
}

/*
    Simply write payload to given file name
*/
void writeToDisk(void *payload, char *pathToWrite, int size)
{
    FILE *outfile = fopen(pathToWrite, "w");
    fwrite(payload, sizeof(char), size, outfile);
    fclose(outfile);
}

unsigned char *decrypt(unsigned char *encrypted, unsigned int input_length, unsigned int original_size)
{
    unsigned char encrypted_msg[input_length - 24];
    unsigned char nonce[24];
    unsigned char key[crypto_secretbox_KEYBYTES];
    FILE *fp_k;

    const unsigned int ciphertext_len = original_size + 16;

    unsigned char *decrypted = calloc(original_size, sizeof(unsigned char));

    if (sodium_init() != 0)
    {
        return NULL;
    }
    // to delete in final
    if ((fp_k = fopen("../test_files/secret-key", "rb")) == NULL)
    {
        puts("Error.");
        return NULL;
    }

    if (fread(key, sizeof(unsigned char), crypto_secretbox_KEYBYTES, fp_k) != crypto_secretbox_KEYBYTES)
    {
        return NULL;
    }

    fclose(fp_k);
    //end to delete in final

    for (int i = 0; i < input_length; i++)
    {
        if (i > 23)
        {
            encrypted_msg[i - 24] = encrypted[i];
        }
        else
        {
            nonce[i] = encrypted[i];
        }
    }

    if (crypto_secretbox_open_easy(decrypted, encrypted_msg, ciphertext_len, nonce, key) != 0)
    {
        puts("Error decrypt");
        return NULL;
    }

    return decrypted;
}

unsigned char *decompress(unsigned char *decrypted, uLong uncomp_len, uLong compressed_len)
{
    unsigned char *uncompressed = (mz_uint8 *)malloc((size_t)uncomp_len);

    uncompress(uncompressed, &uncomp_len, decrypted, compressed_len);
    free(decrypted);

    return uncompressed;
}

unsigned int getUncompLen(unsigned char *payload){
    puts("getting uncomp");
    unsigned int toRet = (payload[0] | payload[1] << 8 | payload[2] << 16 | payload[3] << 24);
    return toRet;
}

unsigned int getDecryptedLen(unsigned char *payload){
    unsigned int toRet = (payload[4] | payload[5] << 8 | payload[6] << 16 | payload[7] << 24);
    return toRet;
}

unsigned int getEncLen(unsigned char *payload){
    unsigned int toRet = (payload[8] | payload[9] << 8 | payload[10] << 16 | payload[11] << 24);
    return toRet;
}