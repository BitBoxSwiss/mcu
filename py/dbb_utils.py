#!/usr/bin/env python


import json
import base64
import aes # slowaes
import hid # hidapi (requires cython)
import hashlib
import struct


# ----------------------------------------------------------------------------------
#

applen = 225280 # flash size minus bootloader length
chunksize = 8*512
usb_report_size = 64 # firmware > v2.0
report_buf_size = 4096 # firmware v2.0.0
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

dbb_hid = hid.device()
def openHid():
    print "\nOpening device"
    dbb_hid.open(0x03eb, 0x2402) # 
    print "\tManufacturer: %s" % dbb_hid.get_manufacturer_string()
    print "\tProduct: %s" % dbb_hid.get_product_string()
    print "\tSerial No: %s\n\n" % dbb_hid.get_serial_number_string()


# ----------------------------------------------------------------------------------
# Firmware io (keep consistent with the Electrum plugin)
#

HWW_CID = 0xFF000000
HWW_CMD = 0x80 + 0x40 + 0x01

def hid_send_frame(data):
    data = bytearray(data)
    data_len = len(data)
    seq = 0;
    idx = 0;
    write = []
    while idx < data_len:
        if idx == 0:
            # INIT frame
            write = data[idx : idx + min(data_len, usb_report_size - 7)]
            dbb_hid.write('\0' + struct.pack(">IBH",HWW_CID, HWW_CMD, data_len & 0xFFFF) + write + '\xEE' * (usb_report_size - 7 - len(write)))
        else: 
            # CONT frame
            write = data[idx : idx + min(data_len, usb_report_size - 5)]
            dbb_hid.write('\0' + struct.pack(">IB", HWW_CID, seq) + write + '\xEE' * (usb_report_size - 5 - len(write)))
            seq += 1
        idx += len(write)


def hid_read_frame():
    # INIT response
    read = dbb_hid.read(usb_report_size)
    cid = ((read[0] * 256 + read[1]) * 256 + read[2]) * 256 + read[3]
    cmd = read[4]
    data_len = read[5] * 256 + read[6]
    data = read[7:]
    idx = len(read) - 7;
    while idx < data_len:
        # CONT response
        read = dbb_hid.read(usb_report_size)
        data += read[5:]
        idx += len(read) - 5
    assert cid == HWW_CID, '- USB command ID mismatch'
    assert cmd == HWW_CMD, '- USB command frame mismatch'
    return data


def hid_send_plain(msg):
    print "Sending: {}".format(msg)
    reply = ""
    try:
        serial_number = dbb_hid.get_serial_number_string()
        if serial_number == "dbb.fw:v2.0.0" or serial_number == "dbb.fw:v1.3.2" or serial_number == "dbb.fw:v1.3.1":
            dbb_hid.write('\0' + bytearray(msg) + '\0' * (report_buf_size - len(msg)))
            r = []
            while len(r) < report_buf_size:
                r = r + dbb_hid.read(report_buf_size)
        else:
            hid_send_frame(msg)
            r = hid_read_frame()
        r = str(bytearray(r)).rstrip(' \t\r\n\0')
        r = r.replace("\0", '')
        reply = json.loads(r)
        print "Reply:   {}".format(reply)
    except Exception as e:
        print 'Exception caught ' + str(e)
    return reply


def hid_send_encrypt(msg, password):
    print "Sending: {}".format(msg)
    reply = ""
    try:
        secret = Hash(password)
        msg = EncodeAES(secret, msg)
        reply = hid_send_plain(msg)
        if 'ciphertext' in reply:
            reply = DecodeAES(secret, ''.join(reply["ciphertext"]))
            print "Reply:   {}\n".format(reply)
            reply = json.loads(reply)
        if 'error' in reply:
            password = None
            print "\n\nReply:   {}\n\n".format(reply)
    except Exception as e:
        print 'Exception caught ' + str(e)
    return reply


# ----------------------------------------------------------------------------------
# Bootloader io
#

def sendPlainBoot(msg):
    print "\nSending: {}".format(msg)
    dbb_hid.write('\0' + bytearray(msg) + '\0'*(boot_buf_size_send-len(msg))) 
    reply = []
    while len(reply) < boot_buf_size_reply:    
        reply = reply + dbb_hid.read(boot_buf_size_reply)
    reply = str(bytearray(reply)).rstrip(' \t\r\n\0')
    print "Reply:   {} {}\n\n".format(reply[:2], reply[2:])
    return reply[1]


def sendChunk(chunknum, data):
    b = bytearray(b"\x77\x00")
    b[1] = chunknum % 0xFF
    b.extend(data)
    dbb_hid.write('\0' + b + '\xFF'*(boot_buf_size_send-len(b))) 
    reply = []
    while len(reply) < boot_buf_size_reply:    
        reply = reply + dbb_hid.read(boot_buf_size_reply)
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

