#!/usr/bin/env python

import sys
from dbb_utils import *


try:

    pw = '0000'

    openHid()


    # Start up options - factory reset; initial password setting
    if 0:
        sendEncrypt('{"reset":"__ERASE__"}')
        sendPlain('{"password":"' + pw + '"}')
        sys.exit()


    # Example JSON commands - refer to digitalbitbox.com/api
    msg = '{"backup":"list"}' 
    msg = '{"seed":{"source": "create"}}'
    msg = '{"device":"info"}'
    msg = '{"random":"pseudo"}' 
    msg = '{"bootloader":"lock"}' 
    msg = '{"bootloader":"unlock"}' 
    msg = '{"led":"blink"}' 


    # Send a JSON command
    sendEncrypt(msg, pw)


except IOError, ex:
    print ex
except (KeyboardInterrupt, SystemExit):
    print "Exiting code"

dbb.close()

