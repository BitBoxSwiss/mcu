#!/usr/bin/env python

import sys
import json
import base64
import hashlib
import hid # hidapi (requires cython)
import aes # slowaes


# AES encryption
EncodeAES = lambda secret, s: base64.b64encode(aes.encryptData(secret,s))
DecodeAES = lambda secret, e: aes.decryptData(secret, base64.b64decode(e))

b64  = lambda i: base64.b64encode(i)
ub64 = lambda i: base64.b64decode(i)

report_buf_size = 4096

def sha256(x):
    return hashlib.sha256(x).digest()

def Hash(x):
    if type(x) is unicode: x=x.encode('utf-8')
    return sha256(sha256(x))


def sendPlain(msg):
    print "\nSending: {}".format(msg)
    dbb.write('\0' + bytearray(msg) + '\0'*(report_buf_size-len(msg))) 
    r = []
    while len(r) < report_buf_size:    
        r = r + dbb.read(report_buf_size)
    reply = str(bytearray(r)).rstrip(' \t\r\n\0')
    print "Reply:   {}\n\n".format(reply)


def sendEncrypt(msg):
    print "\nSending: {}".format(msg)
    try:
        msg = EncodeAES(secret,msg) # ret_byte[0:15]==iv, ret_byte[16:31]=cipher
        dbb.write('\0' + bytearray(msg) + '\0'*(report_buf_size-len(msg))) 
        r = []
        while len(r) < report_buf_size:    
            r = r + dbb.read(report_buf_size)
        r = str(bytearray(r)).rstrip(' \t\r\n\0')
        r = r.replace("\0", '')
        print "Reply: " + r
        reply = json.loads(r)

        if 'ciphertext' in reply:
            reply = DecodeAES(secret, ''.join(reply["ciphertext"]))
            print reply
            reply = json.loads(reply)
        
        if 'error' in reply:
            print 'reply error'
            print reply
        
    except Exception as e:
        print 'Exception caught ' + str(e)
        print r



# ----------------------------------------------------------------------------------
try:
    print "\nOpening device"
    dbb = hid.device()
    dbb.open(0x03eb, 0x2402) # 
    print "\tManufacturer: %s" % dbb.get_manufacturer_string()
    print "\tProduct: %s" % dbb.get_product_string()
    print "\tSerial No: %s\n\n" % dbb.get_serial_number_string()


    # Password to use
    pw     = '0000'
    secret = Hash(pw)


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
    msg = '{"led":"toggle"}' 
   
    # Send a JSON command
    sendEncrypt(msg)


except IOError, ex:
    print ex
except (KeyboardInterrupt, SystemExit):
    print "Exiting code"
# ----------------------------------------------------------------------------------


print "Closing device"
dbb.close()



