#
# This decrypts the API response used in 2023 for some fileopen DRM server API.
# Example: Nascv=2&Nasct=12345&Nasca=121&Nasce=101&Nascd=qwfrhqwhWFQFhfeaf
# (values are made up)
# Nascv: version encoding. Only "2" currently known.
# Nasct: timestamp that is ignored in the official fileopen client
# Nasca: choses the encryption key for the encrypted data by indexing a code table
# Nascd: base64 encoded encrypted data

from Crypto.Cipher import ARC4
import sys
import base64
import hashlib
import struct
import argparse

# encryption key table
CODES = b'\xd2\x8a\x81\x66\x90\xde\x49\x98\x90\xde\x49\x98\x94\xb1\x06\x0b\xa8\xf5\xed\xaf\x3e\xc9\x8a\xb4\x1c\x90\x23\x2b\x48\x73\x2d\x5b\x07\xe8\x03\x4d\x9c\x6e\x4c\xb0\x16\x18\x93\x30\x84\x92\x9d\xba\xd4\xdb\x8c\xab\x7f\xce\x17\xdb\x7e\x50\xe3\x70\x6d\xf5\x00\x93\xd4\xdb\x8c\xab\xe9\x21\xc6\x58\x6c\x52\x3d\x5f\x54\x4f\xef\xd9\x66\x10\xaf\xb4\x37\x39\x22\x83\x75\xab\x4a\xcb\xc1\xa5\x5f\xd6\xce\xb9\xc7\xc6\x5f\xa8\x1b\x92\xa2\xdd\x0f\xa0\x1c\x36\x34\x21\x7c\x63\xbc\xa3\x95\xd9\x8f\x8c\x55\xb7\x52\xa3\xc7\x6d\x5f\x88\x83\x72\x5a\x45\x41\xa8\x80\x33\x80\xf1\xa3\x34\x08\x0f\x80\x8e\xd9\x2d\x1d\x65\xc4\xb9\x6a\x4c\x48\x5e\x19\x69\x90\x18\x91\xd5\x82\x2f\x67\x61\xd3\x5e\x67\xf2\xf8\x84\xdd\xb6\xdb\xd7\x8c\xd5\x7f\x7e\x43\x65\xe2\x4b\xda\xd1\x1a\xb1\xdd\x3a\x8c\x10\xc2\x69\x5e\x87\x0a\x5b\x64\xdc\x0c\x1b\x98\xf4\x03\x41\x00\x7c\x5e\x31\xba\x0b\xe5\x4e\x98\x51\xe2\x06\x74\x89\x3c\x53\x23\xc1\xfb\xab\x85\x8b\x58\xdb\x09\x92\xe6\xd6\xf8\xfd\x46\x7c\xb4\x65\xf3\x29\x8a\x0b\x63\x09\x61\x3d\xc9\x6b\x9b\xce\x45\x05\xc2\x3e\x8b\xc5\x7a\x07\xc2\x6a\xd7\x72\x10\xde\x3a\x1f\xc8\x26\xab\xb1\xfd\xe3\x55\xdd\x65\x5c\x10\x9e\x7c\x87\x0c\x22\xf9\xc3\xe9\x4d\xab\x9b'
def decrypt(nascd, nasca):
    data = base64.b64decode(nascd)
    m = hashlib.md5()
    index = nasca % 256
    m.update(CODES[index:index+12])
    key = m.digest()
    arc4 = ARC4.new(key)
    return arc4.decrypt(data)

parser = argparse.ArgumentParser(description="FileOpen API response decoder")
parser.add_argument('nasca', type=int, help='encryption key table index, from Nasca body field')
parser.add_argument('nascd', help='base64 encoded encrypted data, from Nascd body field')
args = parser.parse_args()

print(decrypt(args.nascd, args.nasca))

