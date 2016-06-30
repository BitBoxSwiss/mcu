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

    with open(padfile, 'ab') as f:
        f.write(sig)
        f.write(binfile)
        f.close()

    with file(binfile, 'r') as original: 
        data = original.read()

    with file(padfile, 'w') as modified: 
        modified.write(sig + data)

except:
    print '\n\nUsage:\n    ./append_signatures_to_binary.py <binary_file> <output_file> <signature_blob>\n\n\n'
