#!/usr/bin/env python


import json
import base64
import aes # slowaes
import hid # hidapi (requires cython)
import hashlib


# ----------------------------------------------------------------------------------
#

applen = 225280 # flash size minus bootloader length
chunksize = 8*512
report_buf_size = 4096
boot_buf_size_send = 4098
boot_buf_size_reply = 256


# ----------------------------------------------------------------------------------
# Crypto
#

EncodeAES = lambda secret, s: base64.b64encode(aes.encryptData(secret,s))
DecodeAES = lambda secret, e: aes.decryptData(secret, base64.b64decode(e))


def sha256(x):
    return hashlib.sha256(x).digest()


def Hash(x):
    if type(x) is unicode: x=x.encode('utf-8')
    return sha256(sha256(x))


# ----------------------------------------------------------------------------------
# HID
#

dbb = hid.device()
def openHid():
    print "\nOpening device"
    dbb.open(0x03eb, 0x2402) # 
    print "\tManufacturer: %s" % dbb.get_manufacturer_string()
    print "\tProduct: %s" % dbb.get_product_string()
    print "\tSerial No: %s\n\n" % dbb.get_serial_number_string()


# ----------------------------------------------------------------------------------
# Firmware io
#

def sendPlain(msg):
    print "\nSending: {}".format(msg)
    dbb.write('\0' + bytearray(msg) + '\0'*(report_buf_size-len(msg))) 
    r = []
    while len(r) < report_buf_size:    
        r = r + dbb.read(report_buf_size)
    reply = str(bytearray(r)).rstrip(' \t\r\n\0')
    print "Reply:   {}\n\n".format(reply)


def sendEncrypt(msg, pw):
    print "\nSending: {}".format(msg)
    try:
        secret = Hash(pw)
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
# Bootloader io
#

def sendPlainBoot(msg):
    print "\nSending: {}".format(msg)
    dbb.write('\0' + bytearray(msg) + '\0'*(boot_buf_size_send-len(msg))) 
    reply = []
    while len(reply) < boot_buf_size_reply:    
        reply = reply + dbb.read(boot_buf_size_reply)
    reply = str(bytearray(reply)).rstrip(' \t\r\n\0')
    print "Reply:   {} {}\n\n".format(reply[:2], reply[2:])
    return reply[1]


def sendChunk(chunknum, data):
    b = bytearray(b"\x77\x00")
    b[1] = chunknum % 0xFF
    b.extend(data)
    dbb.write('\0' + b + '\xFF'*(boot_buf_size_send-len(b))) 
    reply = []
    while len(reply) < boot_buf_size_reply:    
        reply = reply + dbb.read(boot_buf_size_reply)
    reply = str(bytearray(reply)).rstrip(' \t\r\n\0')
    print "Loaded: {}  Code: {}".format(chunknum, reply)


def sendBin(filename):    
    with open(filename, "rb") as f:
        cnt = 0
        while True:     
            data = f.read(chunksize)
            if data == "":
                break
            sendChunk(cnt, data)
            cnt += 1

