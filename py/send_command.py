#!/usr/bin/env python

import sys
from dbb_utils import *


try:

    password = '0000'

    openHid()


    # Start up options - factory reset; initial password setting
    if 0:
        hid_send_encrypt('{"reset":"__ERASE__"}')
        hid_send_plain('{"password":"' + password + '"}')
        sys.exit()


    # Example JSON commands - refer to digitalbitbox.com/api
    message = '{"backup":"list"}' 
    message = '{"device":"info"}'
    message = '{"random":"pseudo"}' 
    message = '{"bootloader":"lock"}' 
    message = '{"bootloader":"unlock"}' 
    message = '{"feature_set":{"U2F":false}}' 
    message = '{"led":"blink"}' 


    # Send a JSON command
    hid_send_encrypt(message, password)


except IOError, ex:
    print ex
except (KeyboardInterrupt, SystemExit):
    print "Exiting code"

dbb_hid.close()

