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
#include "sharedsecret.h"
#include "aescbcb64.h"
#include "base64.h"
#include "flags.h"
#include "utils.h"
#include "utest.h"
#include "hmac.h"
#include "sha2.h"
#include "aes.h"


/**
 * Performs an hmac sha256 message integrity check and returns 0 if the integrity check
 * failed and 1 if it succeeded.
 */
static int check_hmac_sha256(const uint8_t *key, const uint32_t keylen,
                             const unsigned char *in,
                             const unsigned int length, const uint8_t *hmac)
{
    uint8_t verify_hmac[SHA256_DIGEST_LENGTH];
    hmac_sha256(key, keylen, in, length, verify_hmac);
    if (MEMEQ(hmac, verify_hmac, SHA256_DIGEST_LENGTH)) {
        return 1;
    }
    return 0;
}


static char *decrypt_and_check_hmac(const unsigned char *in, int inlen, int *out_msg_len,
                                    const uint8_t *shared_secret, uint8_t *out_hmac)
{
    if (!in || inlen == 0) {
        return NULL;
    }

    uint8_t encryption_key[SHA256_DIGEST_LENGTH];
    uint8_t authentication_key[SHA256_DIGEST_LENGTH];

    sharedsecret_derive_keys(shared_secret, encryption_key, authentication_key);

    // Unbase64
    int ub64len;
    unsigned char *ub64 = unbase64((const char *)in, inlen, &ub64len);
    if (!ub64) {
        return NULL;
    }
    if ((ub64len % N_BLOCK) || ub64len < N_BLOCK) {
        memset(ub64, 0, ub64len);
        free(ub64);
        return NULL;
    }

    memcpy(out_hmac, ub64 + (ub64len - SHA256_DIGEST_LENGTH), SHA256_DIGEST_LENGTH);
    int hmac_len = ub64len - SHA256_DIGEST_LENGTH;

    char *decrypted = NULL;
    if (check_hmac_sha256(authentication_key, SHA256_DIGEST_LENGTH, ub64, hmac_len,
                          out_hmac)) {
        decrypted = aescbcb64_init_and_decrypt(ub64,
                                               ub64len - SHA256_DIGEST_LENGTH,
                                               out_msg_len,
                                               encryption_key);
    }

    memset(ub64, 0, ub64len);
    free(ub64);
    utils_zero(encryption_key, sizeof(encryption_key));
    utils_zero(authentication_key, sizeof(authentication_key));
    return decrypted;
}


#endif
