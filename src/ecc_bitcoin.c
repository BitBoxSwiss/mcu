/*

 The MIT License (MIT)

 Copyright (c) 2017 Jonas Schnelli

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

#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_ecdh.h"
#include "secp256k1/include/secp256k1_recovery.h"


static secp256k1_context *libsecp256k1_ctx = NULL;

void libsecp256k1_ecc_context_init(void);
void libsecp256k1_ecc_context_destroy(void);
int libsecp256k1_ecc_sign_digest(const uint8_t *private_key, const uint8_t *data,
                                 uint8_t *sig, uint8_t *recid, ecc_curve_id curve);
int libsecp256k1_ecc_sign(const uint8_t *private_key, const uint8_t *msg,
                          uint32_t msg_len, uint8_t *sig, uint8_t *recid, ecc_curve_id curve);
int libsecp256k1_ecc_sign_double(const uint8_t *privateKey, const uint8_t *msg,
                                 uint32_t msg_len, uint8_t *sig, uint8_t *recid, ecc_curve_id curve);
int libsecp256k1_ecc_verify(const uint8_t *public_key, const uint8_t *signature,
                            const uint8_t *msg, uint32_t msg_len, ecc_curve_id curve);
int libsecp256k1_ecc_generate_private_key(uint8_t *private_child,
        const uint8_t *private_master, const uint8_t *z, ecc_curve_id curve);
int libsecp256k1_ecc_isValid(uint8_t *private_key, ecc_curve_id curve);
void libsecp256k1_ecc_get_public_key65(const uint8_t *private_key, uint8_t *public_key,
                                       ecc_curve_id curve);
void libsecp256k1_ecc_get_public_key33(const uint8_t *private_key, uint8_t *public_key,
                                       ecc_curve_id curve);
int libsecp256k1_ecc_ecdh(const uint8_t *pair_pubkey, const uint8_t *rand_privkey,
                          uint8_t *ecdh_secret, ecc_curve_id curve);
int libsecp256k1_ecc_recover_public_key(const uint8_t *sig, const uint8_t *msg,
                                        uint32_t msg_len, uint8_t recid, uint8_t *pubkey_65, ecc_curve_id curve);


struct ecc_wrapper bitcoin_ecc = {
    libsecp256k1_ecc_context_init,
    libsecp256k1_ecc_context_destroy,
    libsecp256k1_ecc_sign_digest,
    libsecp256k1_ecc_sign,
    libsecp256k1_ecc_sign_double,
    libsecp256k1_ecc_verify,
    libsecp256k1_ecc_generate_private_key,
    libsecp256k1_ecc_isValid,
    libsecp256k1_ecc_get_public_key65,
    libsecp256k1_ecc_get_public_key33,
    libsecp256k1_ecc_ecdh,
    libsecp256k1_ecc_recover_public_key,
};


void libsecp256k1_ecc_context_init(void)
{
#ifdef TESTING
    libsecp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                       SECP256K1_CONTEXT_VERIFY);
#else
    libsecp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
#endif

    uint8_t rndm[32] = {0};
    random_bytes(rndm, sizeof(rndm), 0);
    if (secp256k1_context_randomize(libsecp256k1_ctx, rndm)) {
        /* pass */
    }
}


void libsecp256k1_ecc_context_destroy(void)
{
    secp256k1_context_destroy(libsecp256k1_ctx);
}


int libsecp256k1_ecc_sign_digest(const uint8_t *private_key, const uint8_t *data,
                                 uint8_t *sig, uint8_t *recid, ecc_curve_id curve)
{
    (void)(curve);
    secp256k1_ecdsa_recoverable_signature signature;

    if (!libsecp256k1_ctx) {
        libsecp256k1_ecc_context_init();
    }

    if (secp256k1_ecdsa_sign_recoverable(libsecp256k1_ctx, &signature,
                                         (const unsigned char *)data,
                                         (const unsigned char *)private_key, secp256k1_nonce_function_rfc6979, NULL)) {
        int recid_ = 0xFF;
        secp256k1_ecdsa_recoverable_signature_serialize_compact(libsecp256k1_ctx, sig,
                &recid_, &signature);

        if (recid) {
            *recid = recid_;
        }
        return 0;
    } else {
        return 1;
    }
}


int libsecp256k1_ecc_sign(const uint8_t *private_key, const uint8_t *msg,
                          uint32_t msg_len, uint8_t *sig, uint8_t *recid, ecc_curve_id curve)
{
    (void)(curve);
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw(msg, msg_len, hash);
    return libsecp256k1_ecc_sign_digest(private_key, hash, sig, recid, curve);
}


int libsecp256k1_ecc_sign_double(const uint8_t *privateKey, const uint8_t *msg,
                                 uint32_t msg_len, uint8_t *sig, uint8_t *recid, ecc_curve_id curve)
{
    (void)(curve);
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw(msg, msg_len, hash);
    sha256_Raw(hash, SHA256_DIGEST_LENGTH, hash);
    return libsecp256k1_ecc_sign_digest(privateKey, hash, sig, recid, curve);
}


static int libsecp256k1_ecc_verify_digest(const uint8_t *public_key, const uint8_t *hash,
        const uint8_t *sig, ecc_curve_id curve)
{
    (void)(curve);
    int public_key_len;
    secp256k1_ecdsa_signature signature, signorm;
    secp256k1_pubkey pubkey;

    if (!libsecp256k1_ctx) {
        libsecp256k1_ecc_context_init();
    }

    secp256k1_ecdsa_signature_parse_compact(libsecp256k1_ctx, &signature, sig);

    if (public_key[0] == 0x04) {
        public_key_len = 65;
    } else if (public_key[0] == 0x02 || public_key[0] == 0x03) {
        public_key_len = 33;
    } else {
        return 1;
    }

    if (!secp256k1_ec_pubkey_parse(libsecp256k1_ctx, &pubkey, public_key, public_key_len)) {
        return 1;
    }

    secp256k1_ecdsa_signature_normalize(libsecp256k1_ctx, &signorm, &signature);

    if (!secp256k1_ecdsa_verify(libsecp256k1_ctx, &signorm, (const unsigned char *)hash,
                                &pubkey)) {
        return 1;
    }

    return 0; // success
}


int libsecp256k1_ecc_verify(const uint8_t *public_key, const uint8_t *signature,
                            const uint8_t *msg,
                            uint32_t msg_len, ecc_curve_id curve)
{
    (void)(curve);
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw(msg, msg_len, hash);
    return libsecp256k1_ecc_verify_digest(public_key, hash, signature, curve);
}


int libsecp256k1_ecc_generate_private_key(uint8_t *private_child,
        const uint8_t *private_master,
        const uint8_t *z, ecc_curve_id curve)
{
    (void)(curve);
    memcpy(private_child, private_master, 32);
    return secp256k1_ec_privkey_tweak_add(libsecp256k1_ctx, (unsigned char *)private_child,
                                          (const unsigned char *)z);
}


int libsecp256k1_ecc_isValid(uint8_t *private_key, ecc_curve_id curve)
{
    (void)(curve);
    if (!libsecp256k1_ctx) {
        libsecp256k1_ecc_context_init();
    }
    return (secp256k1_ec_seckey_verify(libsecp256k1_ctx, (const unsigned char *)private_key));
}


static void libsecp256k1_ecc_get_pubkey(const uint8_t *private_key, uint8_t *public_key,
                                        size_t public_key_len, int compressed)
{
    secp256k1_pubkey pubkey;

    memset(public_key, 0, public_key_len);

    if (!libsecp256k1_ctx) {
        libsecp256k1_ecc_context_init();
    }

    if (!secp256k1_ec_pubkey_create(libsecp256k1_ctx, &pubkey,
                                    (const unsigned char *)private_key)) {
        return;
    }

    if (!secp256k1_ec_pubkey_serialize(libsecp256k1_ctx, public_key, &public_key_len, &pubkey,
                                       compressed)) {
        return;
    }

    return;
}


void libsecp256k1_ecc_get_public_key65(const uint8_t *private_key, uint8_t *public_key,
                                       ecc_curve_id curve)
{
    (void)(curve);
    libsecp256k1_ecc_get_pubkey(private_key, public_key, 65, SECP256K1_EC_UNCOMPRESSED);
}


void libsecp256k1_ecc_get_public_key33(const uint8_t *private_key, uint8_t *public_key,
                                       ecc_curve_id curve)
{
    (void)(curve);
    libsecp256k1_ecc_get_pubkey(private_key, public_key, 33, SECP256K1_EC_COMPRESSED);
}


int libsecp256k1_ecc_ecdh(const uint8_t *pair_pubkey, const uint8_t *rand_privkey,
                          uint8_t *ecdh_secret, ecc_curve_id curve)
{
    (void)(curve);
    uint8_t ecdh_secret_compressed[33];
    secp256k1_pubkey pubkey_secp;

    if (!rand_privkey || !pair_pubkey) {
        return 1;
    }

    if (!libsecp256k1_ctx) {
        libsecp256k1_ecc_context_init();
    }

    if (!secp256k1_ec_pubkey_parse(libsecp256k1_ctx, &pubkey_secp, pair_pubkey, 33)) {
        return 1;
    }

    if (!secp256k1_ecdh(libsecp256k1_ctx, ecdh_secret_compressed, &pubkey_secp,
                        rand_privkey, NULL, NULL)) {
        return 1;
    }

    sha256_Raw(ecdh_secret_compressed + 1, 32, ecdh_secret);
    sha256_Raw(ecdh_secret, 32, ecdh_secret);

    return 0; // success
}


int libsecp256k1_ecc_recover_public_key(const uint8_t *sig, const uint8_t *msg,
                                        uint32_t msg_len, uint8_t recid, uint8_t *pubkey_65, ecc_curve_id curve)
{
    (void)(curve);
    uint8_t msg_hash[32];
    size_t public_key_len = 65;
    secp256k1_ecdsa_recoverable_signature signature;
    secp256k1_pubkey pubkey_recover;

    if (!libsecp256k1_ctx) {
        libsecp256k1_ecc_context_init();
    }

    secp256k1_ecdsa_recoverable_signature_parse_compact(libsecp256k1_ctx, &signature, sig,
            recid);

    sha256_Raw(msg, msg_len, msg_hash);

    if (!secp256k1_ecdsa_recover(libsecp256k1_ctx, &pubkey_recover, &signature, msg_hash)) {
        return 1;
    }

    if (!secp256k1_ec_pubkey_serialize(libsecp256k1_ctx, pubkey_65, &public_key_len,
                                       &pubkey_recover, SECP256K1_EC_UNCOMPRESSED)) {
        return 1;
    }

    return 0; // success
}
