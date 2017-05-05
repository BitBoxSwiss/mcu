/*

 The MIT License (MIT)

 Copyright (c) 2017 Douglas J. Bakkum, Shift Devices AG

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/


#ifndef __U2F_HIJACK_H__
#define __U2F_HIJACK_H__


#include <stdint.h>
#include <stdbool.h>
#include "u2f/u2f.h"


#if !defined(ECC_USE_SECP256K1_LIB) && !defined(TESTING)
#error "ETH mode requires ECC_USE_SECP256K1_LIB"
#endif


#define U2F_HIJACK_CMD 0xdb
#define U2F_HIJACK_OP_XPUB 0x02
#define U2F_HIJACK_OP_SIGN 0x04
#define U2F_HIJACK_ETH_MODE 0xe0
#define U2F_HIJACK_ETH_KEYPATH "m/44'/60'/0'/0"
#define U2F_HIJACK_ETC_KEYPATH "m/44'/61'/0'/0"
#define U2F_HIJACK_TST_KEYPATH "m/44'/1'/0'/0"
#define U2F_HIJACK_ETH_KEYPATH_LEN 14
#define U2F_HIJACK_ETC_KEYPATH_LEN 14
#define U2F_HIJACK_TST_KEYPATH_LEN 13
#define U2F_HIJACK_RESP_DATA_MAX_LEN (256 - U2F_CTR_SIZE - 4)// 120 (can be larger if necessary later)
#define U2F_HIJACK_REQ_DATA_MAX_LEN 64
#define U2F_HIJACK_REQ_KEYPATH_MAX_LEN (U2F_MAX_KH_SIZE - U2F_HIJACK_REQ_DATA_MAX_LEN - U2F_NONCE_LENGTH - 4)// 28


#if (U2F_HIJACK_REQ_DATA_MAX_LEN * 2 + 64 + 1 + 4 > U2F_HIJACK_RESP_DATA_MAX_LEN)
#error "U2F_HIJACK_RESP_DATA_MAX_LEN may not be large enough"
#endif


extern const uint8_t U2F_HIJACK_CODE[32];


typedef struct {
    uint8_t flags;
    uint8_t ctr[U2F_CTR_SIZE];
    uint8_t data[U2F_HIJACK_RESP_DATA_MAX_LEN];
    uint16_t status;
    uint8_t sw1, sw2;
} U2F_RESP_HIJACK;


typedef struct {
    uint8_t cmd;
    uint8_t mode;
    uint8_t op;
    uint8_t password[U2F_NONCE_LENGTH];
    uint8_t data[U2F_HIJACK_REQ_DATA_MAX_LEN];
    uint8_t keypathlen;
    uint8_t keypath[U2F_HIJACK_REQ_KEYPATH_MAX_LEN];
} U2F_REQ_HIJACK;


void u2f_hijack(const U2F_REQ_HIJACK *req);


#endif
