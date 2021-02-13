#include "helpers.h"

/*
    Get size in bytes of given file
*/
int fsize(FILE *fp){
    int prev=ftell(fp);
    fseek(fp, 0L, SEEK_END);
    int sz=ftell(fp);
    fseek(fp,prev,SEEK_SET); //go back to where we were
    return sz;
}

/*
    Execute payload in memory.
    Return 1 on success, 0 on failure.
*/
int executePayload(int payload_fd, char **payload_argv, char **payload_envp){
    if (fexecve(payload_fd, (char * const *) payload_argv, (char * const *) payload_envp) == -1){ // execute payload
        puts("fexecve() failed");
        return 0;
    }
    return 1;
}

/*
    Simply write payload to given file name
*/ 
void writeToDisk(void *payload, char *pathToWrite, int size){
    FILE *outfile = fopen(pathToWrite, "w");
    fwrite(payload, sizeof(char), size, outfile);
    fclose(outfile);
}

static int decrypt(const char* target_file, const char* source_file, const unsigned char key[crypto_secretbox_KEYBYTES]) {
  const unsigned int input_length = 17374;
  unsigned char encrypted[input_length];
  unsigned char encrypted_msg[input_length-24];
  unsigned char nonce[24];

  FILE * stream;

  stream = fopen(source_file, "rb");
  fread(&encrypted, sizeof(unsigned char), input_length, stream);
  fclose(stream);

  for(int i = 0; i<input_length;i++){
    if(i > 23) {
      encrypted_msg[i-24] = encrypted[i];
    } else {
      nonce[i] = encrypted[i];
    } 
   }

  const unsigned int original_size = 17334;
  const unsigned int ciphertext_len = original_size + 16;

  unsigned char decrypted[original_size];
  
  if(crypto_secretbox_open_easy(decrypted, encrypted_msg, ciphertext_len, nonce, key) != 0) {
    puts("Error decrypt");
    return 1;
  }

  FILE * outfile = fopen(target_file, "wb");
  fwrite(decrypted, sizeof(unsigned char), original_size, outfile);
  fclose(outfile);

  return 0;
}

int decompress(void){
  unsigned char  key[crypto_secretbox_KEYBYTES];
  FILE * fp_k;
  unsigned char *uncompressed;
  uLong uncomp_len = 53510; //This is the 3rd part of the filename -- need to change
  uLong compressed_len = 17334;


  if (sodium_init() != 0) {
      return 1;
  }

  if ((fp_k = fopen("./secret-key", "rb")) ==NULL) {
    puts("Error.");
    return -1;
  }

  if (fread(key, sizeof(unsigned char), crypto_secretbox_KEYBYTES, fp_k) != crypto_secretbox_KEYBYTES) {
    return -1;
  }

  fclose(fp_k);

  if (decrypt("./decrypted", "./53510.17334.17374", key) != 0) {
    return 1;
  }

  FILE * infile = fopen("./decrypted", "rb");
  unsigned char decrypted[uncomp_len];
  fread(decrypted, sizeof(unsigned char), uncomp_len, infile);
  uncompressed = (mz_uint8 *)malloc((size_t)uncomp_len);

  fclose(infile);

  uncompress(uncompressed, &uncomp_len, decrypted, compressed_len);

  FILE * outfile = fopen("./uncompressed", "w");

  fwrite(uncompressed, 1, uncomp_len, outfile);

  fclose(outfile);

  return 0;
}