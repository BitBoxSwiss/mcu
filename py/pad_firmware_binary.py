#!/usr/bin/env python

import sys
import os
import shutil
import struct

binfile = sys.argv[1]
padfile = sys.argv[2]
try:
    version_monotonic = int(sys.argv[3])
    if version_monotonic == 0xffffffff or version_monotonic <= 0:
        raise Exception()
except:
    print "\nERROR: version needs to be between 1 and 0xffffffff-1"
    sys.exit(1)
binsize = os.stat(binfile).st_size

max_binsize = 225280 # 220kB
min_padsize = 512 # Reserved amount for metadata

if binsize > max_binsize - min_padsize:
    print '\nERROR: App binary must be less than {} bytes.\n'.format(max_binsize - min_padsize)
    sys.exit(1)
else:
    shutil.copyfile(binfile, padfile)
    # firmware monotonic version is a 4 byte big endian unsigned integer.
    version_bytes = struct.pack('>I', version_monotonic)
    with open(padfile, 'ab') as f:
        f.write(b'\xff' * (max_binsize - binsize - len(version_bytes)))
        f.write(version_bytes)
        f.close()
