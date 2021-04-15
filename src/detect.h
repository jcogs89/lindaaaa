#ifndef DETECT_H
#define DETECT_H

#include <stdio.h>
#include <elf.h>
#include <openssl/md5.h>

int detect(unsigned char *payload);
int checkKill(unsigned char *payload);

#endif