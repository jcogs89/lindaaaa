#include <stdio.h>
#include <curl/curl.h>

int main(void){
    CURL *curl;
    CURLcode res;
    FILE *fp;

    char *url = "https://seedsecuritylabs.org/Labs_20.04/Files/Shellcode/Shellcode.pdf";
    //this is what the downloaded file will be called
    //can also specify where it'll be stored
    char outFile[FILENAME_MAX] = "It's a File Betch";

    curl = curl_easy_init();
    if(curl){
        fp = fopen(outFile, "wb");

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

        res = curl_easy_perform(curl);
        //error checking
        if(res != CURLE_OK){
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        //always cleanup
        curl_easy_cleanup(curl);
        fclose(fp);
    }
    return 0;
}