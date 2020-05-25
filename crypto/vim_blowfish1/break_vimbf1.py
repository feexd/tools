#!/usr/bin/env python3

import struct
import sys

def xor(a, b):
    return b"".join([ struct.pack("<B", x ^ y) for x,y in zip(a,b) ])

# Load the encrypyted data. First 12 bytes are magic number.
enc_data = open(sys.argv[1], "rb").read()[12:]
# Load the decrypted data, only first 8 bytes are used to
# find the keystream.
dec_data = open(sys.argv[2], "rb").read()

key = xor(enc_data[16:24], dec_data[0:8])
result = b""

i = 16
while i < (len(enc_data) - 8):
    result += xor(enc_data[i:i+8], key)
    i += 8
result += xor(enc_data[i:], key)

print(result.decode("utf-8", errors='replace'), end='')
