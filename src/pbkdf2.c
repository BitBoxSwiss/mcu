/*

 The MIT License (MIT)

 Copyright (c) 2015-2016 Douglas J. Bakkum

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


#include <string.h>
#include "pbkdf2.h"
#include "utils.h"
#include "hmac.h"
#include "sha2.h"


void pbkdf2_hmac_sha512(const uint8_t *pass, int passlen, const char *salt, uint8_t *key,
                        int keylen)
{
    uint32_t i, j, k;
    uint8_t f[PBKDF2_HMACLEN], g[PBKDF2_HMACLEN];
    uint32_t blocks = keylen / PBKDF2_HMACLEN;
    int saltlen = strlens(salt);
    uint8_t salt_pbkdf2[saltlen + 4];
    memset(salt_pbkdf2, 0, sizeof(salt_pbkdf2));
    memcpy(salt_pbkdf2, salt, saltlen);

    if (keylen & (PBKDF2_HMACLEN - 1)) {
        blocks++;
    }
    for (i = 1; i <= blocks; i++) {
        salt_pbkdf2[saltlen    ] = (i >> 24) & 0xFF;
        salt_pbkdf2[saltlen + 1] = (i >> 16) & 0xFF;
        salt_pbkdf2[saltlen + 2] = (i >> 8) & 0xFF;
        salt_pbkdf2[saltlen + 3] = i & 0xFF;
        hmac_sha512(pass, passlen, salt_pbkdf2, saltlen + 4, g);
        memcpy(f, g, PBKDF2_HMACLEN);
        for (j = 1; j < PBKDF2_ROUNDS; j++) {
            hmac_sha512(pass, passlen, g, PBKDF2_HMACLEN, g);
            for (k = 0; k < PBKDF2_HMACLEN; k++) {
                f[k] ^= g[k];
            }
        }
        if (i == blocks && (keylen & (PBKDF2_HMACLEN - 1))) {
            memcpy(key + PBKDF2_HMACLEN * (i - 1), f, keylen & (PBKDF2_HMACLEN - 1));
        } else {
            memcpy(key + PBKDF2_HMACLEN * (i - 1), f, PBKDF2_HMACLEN);
        }
    }
    utils_zero(f, sizeof(f));
    utils_zero(g, sizeof(g));
}
