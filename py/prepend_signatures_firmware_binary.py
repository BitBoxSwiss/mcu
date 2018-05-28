#!/usr/bin/env python

import sys
import os
import shutil

try:
    binfile = sys.argv[1]
    padfile = sys.argv[2]
    signatures = sys.argv[3]

    if len(signatures) != 896:
        print '\n\nError:  The signature blob must be an 896-character hexadecimal string.'
        sys.exit()

    sig = bytearray.fromhex(signatures)

    with file(binfile, 'r') as original:
        data = original.read()

    if len(data) != 225280:
        print '\n\nError: the binfile must be padded to 220kB'
        sys.exit()

    with file(padfile, 'w') as pf:
        pf.write(sig)
        pf.write(data)
        pf.close()

except:
    print '\n\nUsage:\n    ./prepend_signatures_firmware_binary.py <firmware_binary> <output_file> <signature_blob>\n\n\n'
