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

#include "commander.h"
#include "memory.h"
#include "base64.h"
#include "random.h"
#include "flags.h"
#include "utils.h"
#include "hmac.h"
#include "sha2.h"
#include "aes.h"
#include "cipher.h"


static void cipher_derive_hmac_keys(const uint8_t *secret,
                                    uint8_t *encryption_key,
                                    uint8_t *authentication_key)
{
    uint8_t hash[SHA512_DIGEST_LENGTH];
    sha512_Raw(secret, SHA256_DIGEST_LENGTH, hash);

    int KEY_SIZE = SHA512_DIGEST_LENGTH / 2;

    memcpy(encryption_key, hash, KEY_SIZE);
    memcpy(authentication_key, hash + KEY_SIZE, KEY_SIZE);

    utils_zero(hash, SHA512_DIGEST_LENGTH);
}


// Must free() returned value
static uint8_t *cipher_aes_encrypt(const unsigned char *in, int inlen,
                                   int *out_len, const uint8_t *key)
{
    int  pads;
    int  inpadlen = inlen + N_BLOCK - inlen % N_BLOCK;
    unsigned char inpad[inpadlen];
    unsigned char enc[inpadlen];
    unsigned char iv[N_BLOCK];
    uint8_t *enc_cat = malloc(sizeof(uint8_t) * (inpadlen +
                              N_BLOCK)); // concatenating [ iv0  |  enc ]

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
        *out_len = 0;
        utils_zero(inpad, inpadlen);
        utils_zero(ctx, sizeof(ctx));
        return NULL;
    }
    memcpy(enc_cat, iv, N_BLOCK);

    // CBC encrypt multiple blocks
    aes_cbc_encrypt(inpad, enc, inpadlen / N_BLOCK, iv, ctx);
    memcpy(enc_cat + N_BLOCK, enc, inpadlen);
    *out_len = inpadlen + N_BLOCK;

    utils_zero(inpad, inpadlen);
    utils_zero(ctx, sizeof(ctx));
    return enc_cat;
}


// Encrypts a given constant char array of length inlen using the AES algorithm with CBC mode
// and base64 encodes the result.
//
// Must free() returned value (allocated inside base64() function)
char *cipher_aes_b64_encrypt(const unsigned char *in, int inlen, int *outb64len,
                             const uint8_t *key)
{
    int outlen;
    uint8_t *encrypt = cipher_aes_encrypt(in, inlen, &outlen, key);
    char *b64;
    b64 = base64(encrypt, outlen, outb64len);
    free(encrypt);
    return b64;
}


// Encrypts a given constant char array of length inlen using the AES algorithm with CBC mode,
// appends its SHA256 HMAC and base64 encodes the result.
//
// Must free() returned value
char *cipher_aes_b64_hmac_encrypt(const unsigned char *in, int inlen, int *outb64len,
                                  const uint8_t *secret)
{
    int outlen;
    uint8_t *hmac_encrypt = cipher_aes_hmac_encrypt(in, inlen, &outlen, secret);
    char *b64 = base64(hmac_encrypt, outlen, outb64len);
    free(hmac_encrypt);
    return b64;
}


// Encrypts a given constant char array of length inlen using the AES algorithm with CBC mode
// and appends its SHA256 HMAC.
//
// Must free() returned value
uint8_t *cipher_aes_hmac_encrypt(const unsigned char *in, int inlen, int *outlen,
                                 const uint8_t *secret)
{
    int encrypt_len;
    uint8_t hmac[SHA256_DIGEST_LENGTH];
    uint8_t encryption_key[SHA256_DIGEST_LENGTH];
    uint8_t authentication_key[SHA256_DIGEST_LENGTH];

    *outlen = 0;

    cipher_derive_hmac_keys(secret, encryption_key, authentication_key);

    uint8_t *encrypted = cipher_aes_encrypt(in,
                                            inlen,
                                            &encrypt_len,
                                            encryption_key);

    if (encrypted == NULL) {
        return NULL;
    }

    hmac_sha256(authentication_key, SHA256_DIGEST_LENGTH, encrypted, encrypt_len, hmac);

    *outlen = encrypt_len + SHA256_DIGEST_LENGTH;
    uint8_t *encrypted_r = realloc(encrypted, *outlen);
    if (encrypted_r == NULL) {
        free(encrypted);
        return NULL;
    }
    encrypted = encrypted_r;

    memcpy(encrypted + encrypt_len, hmac, SHA256_DIGEST_LENGTH);
    utils_zero(encryption_key, sizeof(encryption_key));
    utils_zero(authentication_key, sizeof(authentication_key));

    return encrypted;
}


static char *cipher_aes_decrypt(const uint8_t *in, int inlen, int *outlen,
                                const uint8_t *key)
{
    *outlen = 0;

    // Set cipher key
    aes_context ctx[1];
    memset(ctx, 0, sizeof(ctx));
    aes_set_key(key, 32, ctx);

    unsigned char dec_pad[inlen - N_BLOCK];
    uint8_t iv[N_BLOCK];
    memcpy(iv, in, N_BLOCK);
    aes_cbc_decrypt(in + N_BLOCK, dec_pad, inlen / N_BLOCK - 1, iv, ctx);

    // Strip PKCS7 padding
    int padlen = dec_pad[inlen - N_BLOCK - 1];
    if (inlen - N_BLOCK - padlen <= 0) {
        utils_zero(dec_pad, sizeof(dec_pad));
        utils_zero(ctx, sizeof(ctx));
        return NULL;
    }
    char *dec = malloc(inlen - N_BLOCK - padlen + 1); // +1 for null termination
    if (!dec) {
        utils_zero(dec_pad, sizeof(dec_pad));
        utils_zero(ctx, sizeof(ctx));
        return NULL;
    }
    memcpy(dec, dec_pad, inlen - N_BLOCK - padlen);
    dec[inlen - N_BLOCK - padlen] = '\0';
    *outlen = inlen - N_BLOCK - padlen + 1;
    utils_zero(dec_pad, sizeof(dec_pad));
    utils_zero(ctx, sizeof(ctx));
    return dec;
}


char *cipher_aes_hmac_decrypt(const uint8_t *in, int inlen,
                              int *outlen, const uint8_t *key)
{
    uint8_t hmac[SHA256_DIGEST_LENGTH];
    uint8_t encryption_key[SHA256_DIGEST_LENGTH];
    uint8_t authentication_key[SHA256_DIGEST_LENGTH];

    *outlen = 0;

    if ((size_t)inlen < sizeof(hmac)) {
        return NULL;
    }

    cipher_derive_hmac_keys(key, encryption_key, authentication_key);
    hmac_sha256(authentication_key, MEM_PAGE_LEN, in, inlen - sizeof(hmac), hmac);

    if (!MEMEQ(hmac, in + inlen - sizeof(hmac), sizeof(hmac))) {
        utils_zero(encryption_key, sizeof(encryption_key));
        utils_zero(authentication_key, sizeof(authentication_key));
        return NULL;
    }

    char *ret = cipher_aes_decrypt(in, inlen - sizeof(hmac), outlen, encryption_key);

    utils_zero(encryption_key, sizeof(encryption_key));
    utils_zero(authentication_key, sizeof(authentication_key));
    return ret;
}


// Must free() returned value
char *cipher_aes_b64_decrypt(const unsigned char *in, int inlen, int *outlen,
                             const uint8_t *key)
{
    *outlen = 0;

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
        memset(ub64, 0, ub64len);
        free(ub64);
        return NULL;
    }

    char *ret = cipher_aes_decrypt(ub64, ub64len, outlen, key);
    memset(ub64, 0, ub64len);
    free(ub64);
    return ret;
}
