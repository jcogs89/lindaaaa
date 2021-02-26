#include "networking.h"

/*
    Function to overwrite libcurl's default WriteCallback
    Will write all incoming data to passed in MemoryStruct pointer's memory element
    Will keep track of the total size of the incoming data
    Will re-size the struct's memory element when needed
*/
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp){
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
    char *ptr = realloc(mem->memory, mem->size + realsize + 1); // re-size the memory element
    if(ptr == NULL) {
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
struct MemoryStruct getHTTPS(char *url){
    CURL *curl_handle;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory=malloc(1); // will grow, just set to 1 to have it set up
    chunk.size = 0; // size will grow, set to 0 to start

    curl_global_init(CURL_GLOBAL_ALL);

    curl_handle = curl_easy_init();
    if(curl_handle){
        
        curl_easy_setopt(curl_handle, CURLOPT_URL, url); // set url
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback); // set writing function override
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk); // set writing destination

        res = curl_easy_perform(curl_handle);
        //error checking
        if(res != CURLE_OK){
            free(chunk.memory);
            chunk.memory = NULL; // return null pointer for error
            return chunk;
        }

        //always cleanup
        curl_easy_cleanup(curl_handle);
    }
    return chunk;
}