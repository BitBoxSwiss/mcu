/*

 The MIT License (MIT)

 Copyright (c) 2015-2019 Douglas J. Bakkum, Stephanie Stroka, Shift Cryptosecurity

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

#include "ecdh.h"
#include "random.h"
#include "sd.h"
#include "touch.h"
#include "utils.h"
#include "commander.h"
#include "ecc.h"
#include "led.h"
#include "memory.h"
#include "flags.h"
#include "sha2.h"
#include "yajl/src/api/yajl_tree.h"

#define SIZE_BYTE 8

#define SIZE_EC_POINT_COMPRESSED 33
#define SIZE_EC_POINT_COMPRESSED_HEX 66
#define SIZE_EC_PRIVATE_KEY 32

#define SIZE_SHA256_HEX 64

/**
 * Holds the private and public elliptic-curve keypair generated for the DH-key exchange.
 */
typedef struct TFA_EC_Keypair {
    uint8_t private_key[SIZE_EC_PRIVATE_KEY];
    uint8_t public_key[SIZE_EC_POINT_COMPRESSED];
} TFA_EC_Keypair;

// Stores the SHA-256 hash of the ecdh public key from the mobile app.
__extension__ static uint8_t TFA_IN_HASH_PUB[] = {[0 ... SHA256_DIGEST_LENGTH - 1] = 0x00};
__extension__ static uint8_t TFA_ZEROS[] = {[0 ... SHA256_DIGEST_LENGTH - 1] = 0x00};

// Stores the ecdh keypair used in creating the shared secret for the mobile
// app communication.
__extension__ static TFA_EC_Keypair tfa_keypair = {
    {[0 ... SIZE_EC_PRIVATE_KEY - 1] = 0x00},
    {[0 ... SIZE_EC_POINT_COMPRESSED - 1] = 0x00}
};

// The position of the yet-to-be-verified byte.
static uint8_t TFA_VERIFY_BYTEPOS = 0;

// The position of the current 2 bit inside the yet-to-be-verified byte.
// Valid values are 1 to 4.
static uint8_t TFA_VERIFY_BITPOS = 1;

/**
 * Generates a new EC key pair on the SECP256k1 curve and stores it in the address given as a
 * parameter.
 */
static int ecdh_generate_key(TFA_EC_Keypair *keypair)
{
    do {
        if (random_bytes(keypair->private_key, sizeof(keypair->private_key), 0) == DBB_ERROR) {
            return DBB_ERR_MEM_ATAES;
        }
    } while (!bitcoin_ecc.ecc_isValid(keypair->private_key, ECC_SECP256k1));

    ecc_get_public_key33(keypair->private_key, keypair->public_key, ECC_SECP256k1);
    return DBB_OK;
}

/**
 * Processes the { "ecdh" : { "hash_pubkey" : "..." } } command.
 * The command triggers the (re-)generation of a new ECDH keypair,
 * which requires a long-touch.
 * If an error happens, the function prepares a response.
 */
static void ecdh_hash_pubkey_command(const char *pair_hash_pubkey)
{
    if (strlens(pair_hash_pubkey) != SIZE_SHA256_HEX) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_KEY_HASH_ECDH_LEN);
        return;
    }

    int status = touch_button_press(TOUCH_LONG_PAIR);
    if (status != DBB_TOUCHED) {
        utils_zero(TFA_IN_HASH_PUB, SHA256_DIGEST_LENGTH);
        commander_fill_report(cmd_str(CMD_ecdh), NULL, status);
        return;
    }

    TFA_VERIFY_BITPOS = 1;
    TFA_VERIFY_BYTEPOS = 0;
    int ret = ecdh_generate_key(&tfa_keypair);
    if (ret != DBB_OK) {
        utils_zero(TFA_IN_HASH_PUB, SHA256_DIGEST_LENGTH);
        commander_fill_report(cmd_str(CMD_ecdh), NULL, ret);
        return;
    }

    char msg[256];
    uint8_t hash_pubkey[SHA256_DIGEST_LENGTH];
    sha256_Raw(tfa_keypair.public_key, sizeof(tfa_keypair.public_key), hash_pubkey);
    snprintf(msg, sizeof(msg), "{\"%s\":\"%s\"}",
             cmd_str(CMD_hash_pubkey), utils_uint8_to_hex(hash_pubkey, sizeof(hash_pubkey)));

    memcpy(TFA_IN_HASH_PUB, utils_hex_to_uint8(pair_hash_pubkey), SHA256_DIGEST_LENGTH);
    commander_clear_report();
    commander_fill_report(cmd_str(CMD_ecdh), msg, DBB_JSON_ARRAY);
}

/**
 * Process the { "ecdh" : { "pubkey" : "..." } } command.
 * First, we check whether the provided public key is the one to which the pairing partner
 * committed to in a previous request (hash_pubkey).
 * Then, we create the ECDH shared secret and store it in the eeprom.
 * Lastly, the hash of the pairing partner's public key and keypair for generating the shared
 * secret is reset.
 */
static void ecdh_pubkey_command(const char *pair_pubkey)
{
    // 66 bytes because it's the hex representation of a compressed EC public key.
    if (strlens(pair_pubkey) != SIZE_EC_POINT_COMPRESSED_HEX) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_KEY_ECDH_LEN);
        goto cleanup;
    }

    uint8_t pair_pubkey_bytes[SIZE_EC_POINT_COMPRESSED];
    memcpy(pair_pubkey_bytes, utils_hex_to_uint8(pair_pubkey), SIZE_EC_POINT_COMPRESSED);

    // Point-at-infinity not allowed
    if (MEMEQ(TFA_ZEROS, pair_pubkey_bytes + 1, SHA256_DIGEST_LENGTH)) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_TFA_HASH_MATCH);
        goto cleanup;
    }

    // Check if hashed pubkey was provided
    if (MEMEQ(TFA_ZEROS, TFA_IN_HASH_PUB, SHA256_DIGEST_LENGTH)) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_TFA_HASH_MATCH);
        goto cleanup;
    }

    uint8_t h[SHA256_DIGEST_LENGTH];
    sha256_Raw(pair_pubkey_bytes, SIZE_EC_POINT_COMPRESSED, h);

    // Check if the pubkey matches the provided hashed pubkey
    if (!MEMEQ(h, TFA_IN_HASH_PUB, SHA256_DIGEST_LENGTH)) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_TFA_HASH_MATCH);
        goto cleanup;
    }

    uint8_t ecdh_shared_secret[SIZE_ECDH_SHARED_SECRET];
    if (bitcoin_ecc.ecc_ecdh(pair_pubkey_bytes, tfa_keypair.private_key, ecdh_shared_secret,
                             ECC_SECP256k1)) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_KEY_ECDH);
        goto cleanup;
    }

    uint8_t ret = memory_write_tfa_shared_secret(ecdh_shared_secret);
    if (ret != DBB_OK) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, ret);
        goto cleanup;
    }

    char msg[256];
    snprintf(msg, sizeof(msg), "{\"%s\":\"%s\"}",
             cmd_str(CMD_pubkey), utils_uint8_to_hex(tfa_keypair.public_key,
                     sizeof(tfa_keypair.public_key)));

    commander_fill_report(cmd_str(CMD_ecdh), msg, DBB_JSON_OBJECT);

cleanup:
    utils_zero(TFA_IN_HASH_PUB, SHA256_DIGEST_LENGTH);
    utils_zero(&tfa_keypair, sizeof(TFA_EC_Keypair));
    utils_clear_buffers();

}

/**
 * Challenge the pairing by blinking the LED to verify the shared secret.
 * When this command is called, the LED blinks 1 - 4 times to communicate the value of the
 * 2 bits at the current position of the shared secret.
 * The position is advanced afterwards.
 */
static void ecdh_challenge_command(void)
{
    uint8_t *shared_secret = memory_report_aeskey(TFA_SHARED_SECRET);
    uint8_t encryption_and_authentication_key[SHA512_DIGEST_LENGTH];
    uint8_t encryption_and_authentication_challenge[SHA256_DIGEST_LENGTH];

    sha512_Raw(shared_secret, SIZE_ECDH_SHARED_SECRET, encryption_and_authentication_key);
    sha256_Raw(encryption_and_authentication_key, SHA512_DIGEST_LENGTH,
               encryption_and_authentication_challenge);

    uint8_t two_bit = (encryption_and_authentication_challenge[TFA_VERIFY_BYTEPOS] >>
                       (SIZE_BYTE - 2 *
                        TFA_VERIFY_BITPOS)) & 3;

    TFA_VERIFY_BITPOS = (TFA_VERIFY_BITPOS + 1) % 5;
    if (TFA_VERIFY_BITPOS == 0) {
        TFA_VERIFY_BYTEPOS = (TFA_VERIFY_BYTEPOS + 1) % SIZE_ECDH_SHARED_SECRET;
        TFA_VERIFY_BITPOS = 1;
    }
    led_2FA_pairing_code(two_bit + 1);

    utils_zero(encryption_and_authentication_key, SHA512_DIGEST_LENGTH);
    utils_zero(encryption_and_authentication_challenge, SHA256_DIGEST_LENGTH);

    commander_fill_report(cmd_str(CMD_ecdh), attr_str(ATTR_success), DBB_JSON_STRING);
}

/**
 * Aborts the pairing process and thereby resets the positions for blinking.
 */
static void ecdh_abort_command(void)
{
    utils_zero(TFA_IN_HASH_PUB, SHA256_DIGEST_LENGTH);
    utils_zero(&tfa_keypair, sizeof(TFA_EC_Keypair));
    utils_clear_buffers();
    TFA_VERIFY_BITPOS = 1;
    TFA_VERIFY_BYTEPOS = 0;
    commander_fill_report(cmd_str(CMD_ecdh), cmd_str(ATTR_aborted), DBB_JSON_STRING);
}

/**
 * Dispatches the ecdh command. The following commands are accepted:
 *
 * { "ecdh" : { "hash_pubkey" : "..." } }
 * { "ecdh" : { "pubkey" : "..." } }
 * { "ecdh" : { "challenge" : true } }
 * { "ecdh" : { "abort" : true } }
 */
void ecdh_dispatch_command(yajl_val json_node)
{
    const char *value_path[] = { cmd_str(CMD_ecdh), NULL };

    yajl_val data = yajl_tree_get(json_node, value_path, yajl_t_any);

    if (YAJL_IS_OBJECT(data)) {
        const char *pair_hash_pubkey_path[] = { cmd_str(CMD_hash_pubkey), NULL };
        const char *pair_hash_pubkey = YAJL_GET_STRING(yajl_tree_get(data, pair_hash_pubkey_path,
                                       yajl_t_string));

        const char *pair_pubkey_path[] = { cmd_str(CMD_pubkey), NULL };
        const char *pair_pubkey = YAJL_GET_STRING(yajl_tree_get(data, pair_pubkey_path,
                                  yajl_t_string));

        const char *pair_challenge_path[] = { cmd_str(CMD_challenge), NULL };
        yajl_val pair_challenge = yajl_tree_get(data, pair_challenge_path, yajl_t_true);

        const char *pair_abort_path[] = { cmd_str(CMD_abort), NULL };
        yajl_val pair_abort = yajl_tree_get(data, pair_abort_path, yajl_t_true);

        if (strlens(pair_hash_pubkey)) {
            ecdh_hash_pubkey_command(pair_hash_pubkey);
        } else if (strlens(pair_pubkey)) {
            ecdh_pubkey_command(pair_pubkey);
        } else if (YAJL_IS_TRUE(pair_challenge)) {
            ecdh_challenge_command();
        } else if (YAJL_IS_TRUE(pair_abort)) {
            ecdh_abort_command();
        } else {
            commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_IO_INVALID_CMD);
        }
    } else {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_IO_INVALID_CMD);
    }
}
