#!/usr/bin/env python

import sys
import os
import shutil
import hashlib
import binascii
import ecdsa
from ecdsa.curves import SECP256k1

binfile = sys.argv[1]
signedbinfile = sys.argv[2]
privatekey = sys.argv[3]
privatekey = ecdsa.SigningKey.from_secret_exponent(int(privatekey, 16), curve = SECP256k1)

applen = 229376 # flash size minus bootloader length
chunksize = 8*512


def sha256(x):
    return hashlib.sha256(x).digest()


def Hash(x):
    if type(x) is unicode: x=x.encode('utf-8')
    return sha256(sha256(x))


def signBin(filename):    
    with open(filename, "rb") as f:
        data = ""
        while True:     
            d = f.read(chunksize)
            if d == "":
                break
            data = data + d
    data = data + '\xFF' * (applen - len(data)) 
    return privatekey.sign_digest_deterministic(Hash(data), hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_string)


def readSig(filename):    
    with open(filename, "rb") as f:
        f.seek(os.stat(filename).st_size - 64)    
        return f.read(64)
         

if os.stat(binfile).st_size > applen:
    print '\nERROR: Firmware must be less than {} bytes.\n'.format(applen)
else:
    sig = signBin(binfile)
    shutil.copyfile(binfile, signedbinfile)
    with open(signedbinfile, 'ab') as f:
        f.write(sig)
        f.close()

    if readSig(signedbinfile) != sig:
        os.remove(signedbinfile)
        print '\nERROR: Could not sign firmware.\n'
    else:
        print '\nFirmware signature: {}\n'.format(binascii.hexlify(sig))
