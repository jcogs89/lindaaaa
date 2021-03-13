#!/usr/bin/python3

import sys

if len(sys.argv) != 2:
    print("Usage:\npython3 {} <password>".format(sys.argv[0]))
    exit(-1)

if len(sys.argv[1]) > 32:
    print("Password must be 1-32 bytes long")
    exit(-1)

formattedPass = ""
for i in sys.argv[1]:
    formattedPass += "\\x" + hex(ord(i) ^ 0x8F)[2:]

print(formattedPass)