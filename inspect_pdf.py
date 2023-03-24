# Decrypts a single object from a PDF file and displays the content.
# Requirements:
# - patched pdfminer.six from this repository
# - pycrypto
# - hashlib


from ppdfminer.pdfparser import PDFParser
from ppdfminer.pdfdocument import PDFDocument
from Crypto.Cipher import ARC4
import sys
import base64
import hashlib
import struct
import zlib
from pprint import pprint
import argparse

def genkey_fileopeninfo(data):
        key = struct.pack('>LB', 0xa4da49de, 0x82)
        hash = hashlib.md5()
        key = hash.update(key)
        spointer4 = struct.pack('>LB', 0xec8d6c58, 0x07)
        key = spointer4
        key = hash.update(key)
        md5 = hash.digest()
        key = md5[0:10]
        return ARC4.new(key).decrypt(data)


def genkey_v2(globalkey, objid, genno):
    objid = struct.pack('<L', objid)[:3]
    genno = struct.pack('<L', genno)[:2]
    key = globalkey.encode('ascii') + objid + genno
    hash = hashlib.md5(key)
    key = hash.digest()[:min(len(globalkey) + 5, 16)]
    return key

def decrypt_rc4(objid, genno, data, globalkey):
    key = genkey_v2(globalkey, objid, genno)
    return ARC4.new(key).decrypt(data)


parser = argparse.ArgumentParser(description="fileopen PDF inspector tools, minimum version for just one encoding scheme using genkey_v2")
parser.add_argument('filename', help="PDF file to inspect")
parser.add_argument('-p', '--password', help="password (fileopen code, object key prefix, expected to be 5 characters here) for decryption")
parser.add_argument('-d', '--decode-object', type=int, help="object id to decode and print")
parser.add_argument('-i', '--info', action='store_true', help="print decoded file open info struct")
args = parser.parse_args()

fp = open(args.filename, "rb")

parser = PDFParser(fp)
doc = PDFDocument(parser)
if args.info:
    pprint(doc.encryption)
    pprint(genkey_fileopeninfo(base64.b64decode(doc.encryption[1]['INFO'])).split(b';'))

if args.decode_object is not None and args.password is not None:
    genno = 0
    objid = args.decode_object
    obj = doc.getobj(objid)
    pprint(obj)
    if 'get_rawdata' in dir(obj):
        decode = decrypt_rc4(args.decode_object, genno, obj.get_rawdata(), args.password)
        # we use a FlateDecode filtered objects compression to verify the key. Unzip the objects data to see
        # a potential error:
        if 'Filter' in obj and 'FlateDecode' in obj['Filter'].name:
            print(zlib.decompress(decode))
        else:
            pprint(decode)
