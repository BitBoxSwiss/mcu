/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 * Copyright (c) 2015-2016 Douglas J. Bakkum
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */


#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdint.h>

#include "ecc.h"
#include "random.h"
#include "utils.h"


static int run_test(unsigned long max_iterations, EC_GROUP *ecgroup, ecc_curve_id curve)
{
    uint8_t sig[64], pub_key33[33], pub_key65[65], priv_key[32], msg[256], buffer[1000],
            hash[32], msg_len = 0, *p;
    uint32_t i, j, p_len = 0;
    int cnt = 0, err = 0;

    SHA256_CTX sha256;
    unsigned long iterations = 0;
    while (iterations < max_iterations) {

        // random message len between 1 and 256
        random_bytes(msg, 1 , 0);
        msg_len = msg[0];

        // create random message
        random_bytes(msg, msg_len, 0);

        // new ECDSA key
        EC_KEY *eckey = EC_KEY_new();
        EC_KEY_set_group(eckey, ecgroup);

        // generate the key
        EC_KEY_generate_key(eckey);
        // copy key to buffer
        p = buffer;
        p_len = i2d_ECPrivateKey(eckey, &p);

        // size of the key is in buffer[8] and the key begins right after that
        i = buffer[8];
        // extract key data
        if (i > 32) {
            for (j = 0; j < 32; j++) {
                priv_key[j] = buffer[j + i - 23];
            }
        } else {
            for (j = 0; j < 32 - i; j++) {
                priv_key[j] = 0;
            }
            for (j = 0; j < i; j++) {
                priv_key[j + 32 - i] = buffer[j + 9];
            }
        }

        if (ecc_sign(priv_key, msg, msg_len, sig, curve)) {
            printf("signing failed\n");
            err++;
            break;
        }

        // generate public key from private key
        ecc_get_public_key33(priv_key, pub_key33, curve);
        ecc_get_public_key65(priv_key, pub_key65, curve);


        // verify the message signature
        if (ecc_verify(pub_key65, sig, msg, msg_len, curve)) {
            printf("verification failed (pub_key_len = 65)\n");
            err++;
            break;
        }
        if (ecc_verify(pub_key33, sig, msg, msg_len, curve)) {
            printf("verification failed (pub_key_len = 33)\n");
            err++;
            break;
        }

        // copy signature to the OpenSSL struct
        ECDSA_SIG *signature = ECDSA_SIG_new();
        BN_bin2bn(sig, 32, signature->r);
        BN_bin2bn(sig + 32, 32, signature->s);

        // compute the digest of the message
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, msg, msg_len);
        SHA256_Final(hash, &sha256);

        // verify all went well, i.e. we can decrypt our signature with OpenSSL
        if (ECDSA_do_verify(hash, 32, signature, eckey) != 1) {
            printf("OpenSSL verification failed\n");
            err++;
            break;
        }
        ECDSA_SIG_free(signature);
        EC_KEY_free(eckey);
        cnt++;
        if ((cnt % 100) == 0) {
            printf("Passed ... %d\n", cnt);
        }
        ++iterations;
    }

    if (err) {
        printf("message to sign:\n%s\n\n", utils_uint8_to_hex(msg, msg_len));
        printf("eckey dump:\n%.*s\n\n", p_len, utils_uint8_to_hex(p, sizeof(buffer)));
    }

    return err;
}


int main(int argc, char *argv[])
{
    EC_GROUP *ecgroup;
    int err = 0;

    random_init();
    ecc_context_init();
#ifdef ECC_USE_SECP256K1_LIB
    bitcoin_ecc.ecc_context_init();
#endif

    unsigned long max_iterations = 1000;
    if (argc == 2) {
        sscanf(argv[1], "%lu", &max_iterations);
    } else if (argc > 2) {
        puts("Zero or one command-line arguments only, exiting....");
    }

    printf("\nTesting curve secp256k1\n");
    ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    err += run_test(max_iterations, ecgroup, ECC_SECP256k1);
    EC_GROUP_free(ecgroup);

#ifndef ECC_USE_SECP256K1_LIB
    // secp256k1 library does not have secp256r1 functionality
    printf("\nTesting curve secp256r1\n");
    ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    err += run_test(max_iterations, ecgroup, ECC_SECP256r1);
    EC_GROUP_free(ecgroup);
#endif

    ecc_context_destroy();
#ifdef ECC_USE_SECP256K1_LIB
    bitcoin_ecc.ecc_context_destroy();
#endif
    return err;
}
