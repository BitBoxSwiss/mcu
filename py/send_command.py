#!/usr/bin/env python

import sys
from dbb_utils import *


try:

    password = '0000'

    openHid()


    # Start up options - factory reset; initial password setting
    if 0:
        hid_send_encrypt('{"reset":"__ERASE__"}', password)
        hid_send_plain('{"password":"' + password + '"}')
        sys.exit()


    # Example JSON commands - refer to digitalbitbox.com/api
    message = '{"led":"blink"}'
    message = '{"backup":"list"}'
    message = '{"device":"info"}'
    message = '{"random":"pseudo"}'
    message = '{"bootloader":"lock"}'
    message = '{"bootloader":"unlock"}'
    message = '{"feature_set":{"U2F":false}}'
    message = '{"seed":{"source":"create", "filename":"testing.pdf", "key":"password"}}'
    message = '{"sign":{"meta":"hash", "data":[{"keypath":"m/1p/1/1/0", "hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},{"keypath":"m/1p/1/1/1", "hash":"123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"}]}}'
    message = '{"sign":{"meta":"hash", "data":[{"keypath":"m/1p/1/1/0", "hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "tweak":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},{"keypath":"m/1p/1/1/1", "hash":"123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"}]}}'


    # Send a JSON command
    hid_send_encrypt(message, password)
    hid_send_encrypt(message, password)


except IOError as ex:
    print(ex)
except(KeyboardInterrupt, SystemExit):
    print("Exiting code")

dbb_hid.close()

