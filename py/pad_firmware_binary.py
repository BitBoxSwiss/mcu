#!/usr/bin/env python

import sys
import os
import shutil

binfile = sys.argv[1]
padfile = sys.argv[2]
binsize = os.stat(binfile).st_size

max_binsize = 225280 # 220kB
min_padsize = 512 # Reserved amount for metadata

if binsize > max_binsize - min_padsize:
    print '\nERROR: App binary must be less than {} bytes.\n'.format(max_binsize - min_padsize)
    sys.exit(1)
else:
    shutil.copyfile(binfile, padfile)
    with open(padfile, 'ab') as f:
        f.write(b'\xff' * (max_binsize - binsize))
        f.close()
