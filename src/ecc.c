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


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sha2.h"
#include "flags.h"
#include "utils.h"
#include "random.h"
#include "ecc.h"

#include "uECC.h"

#ifndef ECC_USE_SECP256K1_LIB
/* link the bitcoin ECC wrapper to uECC if secp256k1 is not available */
struct ecc_wrapper bitcoin_ecc = {
    ecc_context_init,
    ecc_context_destroy,
    ecc_sign_digest,
    ecc_sign,
    ecc_sign_double,
    ecc_verify,
    ecc_generate_private_key,
    ecc_isValid,
    ecc_get_public_key65,
    ecc_get_public_key33,
    ecc_ecdh
};
#endif

static int ecc_rng_function(uint8_t *r, unsigned l)
{
    int ret = random_bytes(r, l, 0);
    if (ret == DBB_OK) {
        return 1;
    }
    return 0;
}


void ecc_context_init(void)
{
    uECC_RNG_Function rng_function = ecc_rng_function;
    uECC_set_rng(rng_function);
}


void ecc_context_destroy(void)
{
    // pass
}

static uECC_Curve ecc_curve_from_id(ecc_curve_id curve)
{
    if (curve == ECC_SECP256r1) {
        return uECC_secp256r1();
    }
    return uECC_secp256k1();
}

int ecc_sign_digest(const uint8_t *private_key, const uint8_t *data, uint8_t *sig,
                    ecc_curve_id curve)
{
    uint8_t tmp[32 + 32 + 64];
    SHA256_HashContext ctx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
    return !uECC_sign_deterministic(private_key, data, SHA256_DIGEST_LENGTH, &ctx.uECC, sig,
                                    ecc_curve_from_id(curve));
}


int ecc_sign(const uint8_t *private_key, const uint8_t *msg, uint32_t msg_len,
             uint8_t *sig, ecc_curve_id curve)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw(msg, msg_len, hash);
    return ecc_sign_digest(private_key, hash, sig, curve);
}


int ecc_sign_double(const uint8_t *privateKey, const uint8_t *msg, uint32_t msg_len,
                    uint8_t *sig, ecc_curve_id curve)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw(msg, msg_len, hash);
    sha256_Raw(hash, SHA256_DIGEST_LENGTH, hash);
    return ecc_sign_digest(privateKey, hash, sig, curve);
}


static int ecc_read_pubkey(const uint8_t *publicKey, uint8_t *public_key_64,
                           ecc_curve_id curve)
{
    if (publicKey[0] == 0x04) {
        memcpy(public_key_64, publicKey + 1, 64);
        return 1;
    } else if (publicKey[0] == 0x02 || publicKey[0] == 0x03) { // compute missing y coords
        uECC_decompress(publicKey, public_key_64, ecc_curve_from_id(curve));
        return 1;
    }
    // error
    return 0;
}


static int ecc_verify_digest(const uint8_t *public_key, const uint8_t *hash,
                             const uint8_t *sig, ecc_curve_id curve)
{
    return uECC_verify(public_key, hash, SHA256_DIGEST_LENGTH, sig, ecc_curve_from_id(curve));
}


int ecc_verify(const uint8_t *public_key, const uint8_t *signature, const uint8_t *msg,
               uint32_t msg_len, ecc_curve_id curve)
{
    uint8_t public_key_64[64];
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw(msg, msg_len, hash);
    ecc_read_pubkey(public_key, public_key_64, curve);
    return !ecc_verify_digest(public_key_64, hash, signature, curve);
}


int ecc_generate_private_key(uint8_t *private_child, const uint8_t *private_master,
                             const uint8_t *z, ecc_curve_id curve)
{
    uECC_generate_private_key(private_child, private_master, z, ecc_curve_from_id(curve));
    return ecc_isValid(private_child, curve);
}


int ecc_isValid(uint8_t *private_key, ecc_curve_id curve)
{
    return uECC_isValid(private_key, ecc_curve_from_id(curve));
}


void ecc_get_public_key65(const uint8_t *private_key, uint8_t *public_key,
                          ecc_curve_id curve)
{
    uint8_t *p = public_key;
    p[0] = 0x04;
    uECC_compute_public_key(private_key, p + 1, ecc_curve_from_id(curve));
}


void ecc_get_public_key33(const uint8_t *private_key, uint8_t *public_key,
                          ecc_curve_id curve)
{
    uint8_t public_key_long[64];
    uECC_compute_public_key(private_key, public_key_long, ecc_curve_from_id(curve));
    uECC_compress(public_key_long, public_key, ecc_curve_from_id(curve));
}


int ecc_ecdh(const uint8_t *pair_pubkey, const uint8_t *rand_privkey,
             uint8_t *ecdh_secret, ecc_curve_id curve)
{
    uint8_t public_key[64];
    uECC_decompress(pair_pubkey, public_key, ecc_curve_from_id(curve));
    if (uECC_shared_secret(public_key, rand_privkey, ecdh_secret, ecc_curve_from_id(curve))) {
        sha256_Raw(ecdh_secret, 32, ecdh_secret);
        sha256_Raw(ecdh_secret, 32, ecdh_secret);
        return 0;
    } else {
        return 1;
    }
}


int ecc_sig_to_der(const uint8_t *sig, uint8_t *der)
{
    int i;
    uint8_t *p = der, *len, *len1, *len2;
    *p = 0x30;
    p++; // sequence
    *p = 0x00;
    len = p;
    p++; // len(sequence)

    *p = 0x02;
    p++; // integer
    *p = 0x00;
    len1 = p;
    p++; // len(integer)

    // process R
    i = 0;
    while (sig[i] == 0 && i < 32) {
        i++; // skip leading zeroes
    }
    if (sig[i] >= 0x80) { // put zero in output if MSB set
        *p = 0x00;
        p++;
        *len1 = *len1 + 1;
    }
    while (i < 32) { // copy bytes to output
        *p = sig[i];
        p++;
        *len1 = *len1 + 1;
        i++;
    }

    *p = 0x02;
    p++; // integer
    *p = 0x00;
    len2 = p;
    p++; // len(integer)

    // process S
    i = 32;
    while (sig[i] == 0 && i < 64) {
        i++; // skip leading zeroes
    }
    if (sig[i] >= 0x80) { // put zero in output if MSB set
        *p = 0x00;
        p++;
        *len2 = *len2 + 1;
    }
    while (i < 64) { // copy bytes to output
        *p = sig[i];
        p++;
        *len2 = *len2 + 1;
        i++;
    }

    *len = *len1 + *len2 + 4;
    return *len + 2;
}
