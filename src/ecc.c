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
#ifndef ECC_USE_UECC_LIB
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_ecdh.h"


static secp256k1_context *ctx = NULL;


void ecc_context_init(void)
{
#ifdef TESTING
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
#else
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
#endif

    uint8_t rndm[32] = {0};
    random_bytes(rndm, sizeof(rndm), 0);
    if (secp256k1_context_randomize(ctx, rndm)) {
        /* pass */
    }
}


void ecc_context_destroy(void)
{
    secp256k1_context_destroy(ctx);
}


int ecc_sign_digest(const uint8_t *private_key, const uint8_t *data, uint8_t *sig)
{
    secp256k1_ecdsa_signature signature;

    if (!ctx) {
        ecc_context_init();
    }

    if (secp256k1_ecdsa_sign(ctx, &signature, (const unsigned char *)data,
                             (const unsigned char *)private_key, secp256k1_nonce_function_rfc6979, NULL)) {
        int i;
        for (i = 0; i < 32; i++) {
            sig[i] = signature.data[32 - i - 1];
            sig[i + 32] = signature.data[64 - i - 1];
        }
        return 0;
    } else {
        return 1;
    }
}


int ecc_sign(const uint8_t *private_key, const uint8_t *msg, uint32_t msg_len,
             uint8_t *sig)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw(msg, msg_len, hash);
    return ecc_sign_digest(private_key, hash, sig);
}


int ecc_sign_double(const uint8_t *privateKey, const uint8_t *msg, uint32_t msg_len,
                    uint8_t *sig)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw(msg, msg_len, hash);
    sha256_Raw(hash, SHA256_DIGEST_LENGTH, hash);
    return ecc_sign_digest(privateKey, hash, sig);
}


static int ecc_verify_digest(const uint8_t *public_key, const uint8_t *hash,
                             const uint8_t *sig)
{

    int public_key_len;
    secp256k1_ecdsa_signature signature, signorm;
    secp256k1_pubkey pubkey;

    if (!ctx) {
        ecc_context_init();
    }

    int i;
    for (i = 0; i < 32; i++) {
        signature.data[32 - i - 1] = sig[i];
        signature.data[64 - i - 1] = sig[i + 32];
    }

    if (public_key[0] == 0x04) {
        public_key_len = 65;
    } else if (public_key[0] == 0x02 || public_key[0] == 0x03) {
        public_key_len = 33;
    } else {
        return 1;
    }

    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, public_key, public_key_len)) {
        return 1;
    }

    secp256k1_ecdsa_signature_normalize(ctx, &signorm, &signature);

    if (!secp256k1_ecdsa_verify(ctx, &signorm, (const unsigned char *)hash, &pubkey)) {
        return 1;
    }

    return 0; // success
}


int ecc_verify(const uint8_t *public_key, const uint8_t *signature, const uint8_t *msg,
               uint32_t msg_len)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw(msg, msg_len, hash);
    return ecc_verify_digest(public_key, hash, signature);
}


int ecc_generate_private_key(uint8_t *private_child, const uint8_t *private_master,
                             const uint8_t *z)
{
    memcpy(private_child, private_master, 32);
    return secp256k1_ec_privkey_tweak_add(ctx, (unsigned char *)private_child,
                                          (const unsigned char *)z);
}


int ecc_isValid(uint8_t *private_key)
{
    if (!ctx) {
        ecc_context_init();
    }
    return (secp256k1_ec_seckey_verify(ctx, (const unsigned char *)private_key));
}


static void ecc_get_pubkey(const uint8_t *private_key, uint8_t *public_key,
                           size_t public_key_len, int compressed)
{
    secp256k1_pubkey pubkey;

    memset(public_key, 0, public_key_len);

    if (!ctx) {
        ecc_context_init();
    }

    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char *)private_key)) {
        return;
    }

    if (!secp256k1_ec_pubkey_serialize(ctx, public_key, &public_key_len, &pubkey,
                                       compressed)) {
        return;
    }

    return;
}


void ecc_get_public_key65(const uint8_t *private_key, uint8_t *public_key)
{
    ecc_get_pubkey(private_key, public_key, 65, SECP256K1_EC_UNCOMPRESSED);
}


void ecc_get_public_key33(const uint8_t *private_key, uint8_t *public_key)
{
    ecc_get_pubkey(private_key, public_key, 33, SECP256K1_EC_COMPRESSED);
}


int ecc_ecdh(const uint8_t *pair_pubkey, const uint8_t *rand_privkey,
             uint8_t *ecdh_secret)
{
    uint8_t ecdh_secret_compressed[33];
    secp256k1_pubkey pubkey_secp;

    if (!rand_privkey || !pair_pubkey) {
        return 1;
    }

    if (!ctx) {
        ecc_context_init();
    }

    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey_secp, pair_pubkey, 33)) {
        return 1;
    }

    if (!secp256k1_ecdh(ctx, ecdh_secret_compressed, &pubkey_secp, rand_privkey)) {
        return 1;
    }

    sha256_Raw(ecdh_secret_compressed + 1, 32, ecdh_secret);
    sha256_Raw(ecdh_secret, 32, ecdh_secret);

    return 0; // success
}


#else


#include "uECC.h"


static uECC_Curve ecc_curve;


static int ecc_rng_function(uint8_t *r, unsigned l)
{
    int ret = random_bytes(r, l, 0);
    if (ret == DBB_OK) {
        return 1;
    }
    return 0;
}


void ecc_set_curve(ecc_curve_id curve)
{
    switch (curve) {
        case ECC_SECP256r1:
            ecc_curve = uECC_secp256r1();
            break;

        case ECC_SECP256k1:
            ecc_curve = uECC_secp256k1();
            break;

        default:
            ecc_curve = uECC_secp256k1();
    }
}


void ecc_context_init(void)
{
    uECC_RNG_Function rng_function = ecc_rng_function;
    uECC_set_rng(rng_function);
    ecc_set_curve(ECC_SECP256k1);
}


void ecc_context_destroy(void)
{
    // pass
}


int ecc_sign_digest(const uint8_t *private_key, const uint8_t *data, uint8_t *sig)
{
    uint8_t tmp[32 + 32 + 64];
    SHA256_HashContext ctx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
    return !uECC_sign_deterministic(private_key, data, SHA256_DIGEST_LENGTH, &ctx.uECC, sig,
                                    ecc_curve);
}


int ecc_sign(const uint8_t *private_key, const uint8_t *msg, uint32_t msg_len,
             uint8_t *sig)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw(msg, msg_len, hash);
    return ecc_sign_digest(private_key, hash, sig);
}


int ecc_sign_double(const uint8_t *privateKey, const uint8_t *msg, uint32_t msg_len,
                    uint8_t *sig)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw(msg, msg_len, hash);
    sha256_Raw(hash, SHA256_DIGEST_LENGTH, hash);
    return ecc_sign_digest(privateKey, hash, sig);
}


static int ecc_read_pubkey(const uint8_t *publicKey, uint8_t *public_key_64)
{
    if (publicKey[0] == 0x04) {
        memcpy(public_key_64, publicKey + 1, 64);
        return 1;
    }
    if (publicKey[0] == 0x02 || publicKey[0] == 0x03) { // compute missing y coords
        uECC_decompress(publicKey, public_key_64, ecc_curve);
        return 1;
    }
    // error
    return 0;
}


static int ecc_verify_digest(const uint8_t *public_key, const uint8_t *hash,
                             const uint8_t *sig)
{
    return uECC_verify(public_key, hash, SHA256_DIGEST_LENGTH, sig, ecc_curve);
}


int ecc_verify(const uint8_t *public_key, const uint8_t *signature, const uint8_t *msg,
               uint32_t msg_len)
{
    uint8_t public_key_64[64];
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw(msg, msg_len, hash);
    ecc_read_pubkey(public_key, public_key_64);
    return !ecc_verify_digest(public_key_64, hash, signature);
}


int ecc_generate_private_key(uint8_t *private_child, const uint8_t *private_master,
                             const uint8_t *z)
{
    uECC_generate_private_key(private_child, private_master, z, ecc_curve);
    return ecc_isValid(private_child);
}


int ecc_isValid(uint8_t *private_key)
{
    return uECC_isValid(private_key, ecc_curve);
}


void ecc_get_public_key65(const uint8_t *private_key, uint8_t *public_key)
{
    uint8_t *p = public_key;
    p[0] = 0x04;
    uECC_compute_public_key(private_key, p + 1, ecc_curve);
}


void ecc_get_public_key33(const uint8_t *private_key, uint8_t *public_key)
{
    uint8_t public_key_long[64];
    uECC_compute_public_key(private_key, public_key_long, ecc_curve);
    uECC_compress(public_key_long, public_key, ecc_curve);
}


int ecc_ecdh(const uint8_t *pair_pubkey, const uint8_t *rand_privkey,
             uint8_t *ecdh_secret)
{
    uint8_t public_key[64];
    uECC_decompress(pair_pubkey, public_key, ecc_curve);
    if (uECC_shared_secret(public_key, rand_privkey, ecdh_secret, ecc_curve)) {
        sha256_Raw(ecdh_secret, 32, ecdh_secret);
        sha256_Raw(ecdh_secret, 32, ecdh_secret);
        return 0;
    } else {
        return 1;
    }
}


#endif
