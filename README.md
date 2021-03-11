# lindaaaa

## Setting up
  * Run `python3 passgen.py password` to create XOR obfuscated password
  * Paste the output of **passgen.py** into **preferences.h** as the value of **ENC_PASSWORD**
  * Ensure all other definitions held within **preferences.h** are correct for current deployment
    * **PAYLOAD_URL** is the URL of of the deployed packer with the correct arguments
      * **"https://127.0.0.1:25566/api/testloader?send=payload-6"** would reach to the packer on localhost at port 25566 and retrieve payload 6
    * **PATH_TO_WRITE** is the path on disk to write any non-executable files
      * May become obsolete as the path may become metadata sent with payload
    * **ENC_PASSWORD** is the symmetric password used for encryption and decryption after it hsa been fed through **passgen.py**
    * **BEACON_MODE** is to set the type of beaconing desired
      * **0** will make the loader beacon only once immediately
      * Any positive number **x** will cause the loader to beacon every **x** seconds until it retrieves the payload, then exit after execution
    * **TODO: BEACON_TIME_DATE** is the time/date in seconds from Jan 1st, 1970 that the beacon will wait until to beacon for the payload
      * **0** will make the loader not wait and simply follow the beaconing mode set in **BEACON_MODE**
      * If this value is set to anything other than **0**, once the specified time/date is reached, the loader will then follow the beaconing mode set by **BEACON_MODE**
  * Compile as outlined below

## Compiling
  * Run `make && make clean` in the /src directory
  * This will generate the lindaaaa executable in the /build directory

## Dependencies
  * libcurl4-openssl-dev
  
## TODO
  * Static compilation
  * BEACON_DATE_TIME
