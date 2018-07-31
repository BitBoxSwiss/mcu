/*

 The MIT License (MIT)

 Copyright (c) 2015-2018 Douglas J. Bakkum

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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aescbcb64.h"
#include "hmac.h"
#include "commander.h"
#include "sharedsecret.h"
#include "memory.h"
#include "base64.h"
#include "aes.h"
#include "sha2.h"
#include "random.h"
#include "flags.h"
#include "utils.h"

// Must free() returned value
static uint8_t *aescbcb64_init_and_encrypt(const unsigned char *in, int inlen,
        int *out_len,
        const uint8_t *key)
{
    int  pads;
    int  inpadlen = inlen + N_BLOCK - inlen % N_BLOCK;
    unsigned char inpad[inpadlen];
    unsigned char enc[inpadlen];
    unsigned char iv[N_BLOCK];
    uint8_t *enc_cat = malloc(sizeof(uint8_t) * (inpadlen +
                              N_BLOCK)); // concatenating [ iv0  |  enc ]
    *out_len = inpadlen + N_BLOCK;

    aes_context ctx[1];

    // Set cipher key
    memset(ctx, 0, sizeof(ctx));
    aes_set_key(key, 32, ctx);

    // PKCS7 padding
    memcpy(inpad, in, inlen);
    for (pads = 0; pads < N_BLOCK - inlen % N_BLOCK; pads++ ) {
        inpad[inlen + pads] = (N_BLOCK - inlen % N_BLOCK);
    }

    // Make a random initialization vector
    if (random_bytes((uint8_t *)iv, N_BLOCK, 0) == DBB_ERROR) {
        commander_fill_report(cmd_str(CMD_random), NULL, DBB_ERR_MEM_ATAES);
        utils_zero(inpad, inpadlen);
        utils_zero(ctx, sizeof(ctx));
        return NULL;
    }
    memcpy(enc_cat, iv, N_BLOCK);

    // CBC encrypt multiple blocks
    aes_cbc_encrypt(inpad, enc, inpadlen / N_BLOCK, iv, ctx);
    memcpy(enc_cat + N_BLOCK, enc, inpadlen);

    utils_zero(inpad, inpadlen);
    utils_zero(ctx, sizeof(ctx));
    return enc_cat;
}


// Must free() returned value (allocated inside base64() function)
char *aescbcb64_encrypt(const unsigned char *in, int inlen, int *out_b64len,
                        const uint8_t *key)
{
    int out_len;
    uint8_t *enc_cat = aescbcb64_init_and_encrypt(in, inlen, &out_len, key);
    // base64 encoding
    char *b64;
    b64 = base64(enc_cat, out_len, out_b64len);
    free(enc_cat);
    return b64;
}

// Encrypts a given constant char array of length inlen using the AES algorithm with CBC mode,
// appends its SHA256 HMAC and base64 encodes the result.
//
// Must free() returned value
char *aescbcb64_hmac_encrypt(const unsigned char *in, int inlen, int *out_b64len,
                             const uint8_t *shared_secret)
{
    uint8_t encryption_key[SHA256_DIGEST_LENGTH];
    uint8_t authentication_key[SHA256_DIGEST_LENGTH];

    sharedsecret_derive_keys(shared_secret, encryption_key, authentication_key);

    int encrypt_len;
    uint8_t *encrypted = aescbcb64_init_and_encrypt(in,
                         inlen,
                         &encrypt_len,
                         encryption_key);
    uint8_t hmac[SHA256_DIGEST_LENGTH];
    hmac_sha256(authentication_key, SHA256_DIGEST_LENGTH, encrypted, encrypt_len, hmac);

    uint8_t authenticated_encrypted_msg[encrypt_len + SHA256_DIGEST_LENGTH];
    memcpy(authenticated_encrypted_msg, encrypted, encrypt_len);
    memcpy(authenticated_encrypted_msg + encrypt_len, hmac, SHA256_DIGEST_LENGTH);

    free(encrypted);
    utils_zero(encryption_key, sizeof(encryption_key));
    utils_zero(authentication_key, sizeof(authentication_key));
    char *b64 = base64(authenticated_encrypted_msg, encrypt_len + SHA256_DIGEST_LENGTH,
                       out_b64len);
    return b64;
}

char *aescbcb64_init_and_decrypt(uint8_t *ub64, int ub64len, int *decrypt_len,
                                 const uint8_t *key)
{
    *decrypt_len = 0;

    // Set cipher key
    aes_context ctx[1];
    memset(ctx, 0, sizeof(ctx));
    aes_set_key(key, 32, ctx);

    unsigned char dec_pad[ub64len - N_BLOCK];
    aes_cbc_decrypt(ub64 + N_BLOCK, dec_pad, ub64len / N_BLOCK - 1, ub64, ctx);

    // Strip PKCS7 padding
    int padlen = dec_pad[ub64len - N_BLOCK - 1];
    if (ub64len - N_BLOCK - padlen <= 0) {
        utils_zero(dec_pad, sizeof(dec_pad));
        utils_zero(ctx, sizeof(ctx));
        return NULL;
    }
    char *dec = malloc(ub64len - N_BLOCK - padlen + 1); // +1 for null termination
    if (!dec) {
        utils_zero(dec_pad, sizeof(dec_pad));
        utils_zero(ctx, sizeof(ctx));
        return NULL;
    }
    memcpy(dec, dec_pad, ub64len - N_BLOCK - padlen);
    dec[ub64len - N_BLOCK - padlen] = '\0';
    *decrypt_len = ub64len - N_BLOCK - padlen + 1;
    utils_zero(dec_pad, sizeof(dec_pad));
    utils_zero(ctx, sizeof(ctx));
    return dec;
}

// Must free() returned value
char *aescbcb64_decrypt(const unsigned char *in, int inlen, int *decrypt_len,
                        const uint8_t *key)
{
    if (!in || inlen == 0) {
        return NULL;
    }

    // Unbase64
    int ub64len;
    unsigned char *ub64 = unbase64((const char *)in, inlen, &ub64len);
    if (!ub64) {
        return NULL;
    }
    if ((ub64len % N_BLOCK) || ub64len < N_BLOCK) {
        free(ub64);
        return NULL;
    }

    char *ret = aescbcb64_init_and_decrypt(ub64, ub64len, decrypt_len, key);
    memset(ub64, 0, ub64len);
    free(ub64);
    return ret;
}


