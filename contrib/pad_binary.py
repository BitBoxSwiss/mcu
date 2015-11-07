import sys
import os
import shutil

binfile = sys.argv[1]
padfile = sys.argv[2]
binsize = os.stat(binfile).st_size

max_binsize = 32768

if binsize > max_binsize:
    print '\nERROR: Bootloader must be less than {} bytes.\n'.format(max_binsize)
else:
    shutil.copyfile(binfile, padfile)
    with open(padfile, 'ab') as f:
        f.write(os.urandom(max_binsize - binsize))
        f.close()
