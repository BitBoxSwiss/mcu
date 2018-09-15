/*

 The MIT License (MIT)

 Copyright (c) 2018 Douglas J. Bakkum, Stephanie Stroka, Shift Cryptosecurity

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


#ifndef _HMAC_CHECK_H_
#define _HMAC_CHECK_H_


#include <stdint.h>
#include "yajl/src/api/yajl_tree.h"
#include "cipher.h"
#include "base64.h"
#include "flags.h"
#include "utils.h"
#include "utest.h"
#include "hmac.h"
#include "sha2.h"
#include "aes.h"


static char *cipher_aes_b64_hmac_decrypt(const unsigned char *in, int inlen,
        int *out_msg_len, const uint8_t *secret)
{
    unsigned char *ub64;
    char *decrypted;
    int ub64len;

    if (!in || inlen == 0 || !secret) {
        return NULL;
    }

    // Unbase64
    ub64 = unbase64((const char *)in, inlen, &ub64len);
    if (!ub64) {
        return NULL;
    }
    if ((ub64len % N_BLOCK) || ub64len < N_BLOCK) {
        memset(ub64, 0, ub64len);
        free(ub64);
        return NULL;
    }

    decrypted = cipher_aes_hmac_decrypt(ub64, ub64len, out_msg_len, secret);

    memset(ub64, 0, ub64len);
    free(ub64);
    return decrypted;
}


#endif
