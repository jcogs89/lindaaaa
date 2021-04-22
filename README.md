# lindaaaa

## Setting up
  * Run `python3 passgen.py password` to create XOR obfuscated password
  * Paste the output of **passgen.py** into **preferences.h** as the value of **ENC_PASSWORD**
  * Ensure all other definitions held within **preferences.h** are correct for current deployment
    * **PAYLOAD_URL** is the URL of of the deployed packer with the correct arguments
      * **"https://127.0.0.1:25566/api/testloader?send="** would reach to the packer on localhost at port 25566 with the loader name testloader 
      * **NOTE** The URL is automatically formatted. All that must be specified in the URL is the IP, port, and loader name
    * **PATH_TO_WRITE** is the path on disk to write any non-executable files
      * May become obsolete as the path may become metadata sent with payload
    * **ENC_PASSWORD** is the symmetric password used for encryption and decryption after it hsa been fed through **passgen.py**
    * **BEACON_MODE** is to set the type of beaconing desired for beaconing for all payloads
      * **0** will make the loader beacon only once immediately
      * Any positive number **x** will cause the loader to beacon every **x** seconds until it retrieves the payload, then exit after execution
      * **-1** will cause loader to beacon once at unix epoch timestamp (in seconds) held in **BEACON_DATE_TIME**
    * **BEACON_DATE_TIME** is the time/date in seconds from Jan 1st, 1970 that the beacon will wait until to beacon for the payload
      * **0** will make the loader not wait and simply follow the beaconing mode set in **BEACON_MODE**
      * Once the specified time/date is reached, the loader will beacon only once
    * **BEACON\*_INITIAL** Follows logic above, but only applies for first beacon for instructions
    * **BEACON\*_INSTRUCTIONS** Follows logic above, but applies to all instructions beacons after the first

## Compiling
  * Run `make && make clean` in the /src directory
  * This will generate the lindaaaa executable in the /build directory

## Dependencies
  * libsodium-dev `apt install libsodium-dev`
  * libcurl4-openssl-dev `apt install libcurl4-openssl-dev`
  * glibc >= 2.27
  
## Unfinished Features
  * Static compilation/linking. I tried for 3 months, if you can get it statically linked (libCurl is what was giving the errors), it has all features requested, plus MANY more outlined in the Packer documentation.
