#ifndef HELPERS_H
#define HELPERS_H

#include <stdio.h>
#include <unistd.h>

int fsize(FILE *fp);
int executePayload(int payload_fd, char **payload_argv, char **payload_envp);
void writeToDisk(void *payload, char *pathToWrite, int size);

#endif