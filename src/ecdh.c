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
#define CHALLENGE_BIT_POSITION_START 1
#define CHALLENGE_BIT_POSITION_MAX 4
#define CHALLENGE_BYTE_POSITION_START 0
#define CHALLENGE_MIN_SETS_BIT_VALUE (((CHALLENGE_MIN_BLINK_SETS - 1) % CHALLENGE_BIT_POSITION_MAX) + CHALLENGE_BIT_POSITION_START)
#define CHALLENGE_MIN_SETS_BYTE_VALUE ((CHALLENGE_MIN_BLINK_SETS - 1) / CHALLENGE_BIT_POSITION_MAX)


/**
 * Holds the private and public elliptic-curve keypair generated for the DH-key exchange.
 */
typedef struct {
    uint8_t private_key[SIZE_EC_PRIVATE_KEY];
    uint8_t public_key[SIZE_EC_POINT_COMPRESSED];
} _keypair_t;

// Stores the SHA-256 hash of the ecdh public key from the mobile app.
__extension__ static uint8_t _input_hash_pubkey[] = {[0 ... SHA256_DIGEST_LENGTH - 1] = 0x00};
__extension__ static uint8_t _zero_32[] = {[0 ... SHA256_DIGEST_LENGTH - 1] = 0x00};

// Stores the ecdh keypair used in creating the shared secret for the mobile
// app communication.
__extension__ static _keypair_t _keypair = {
    {[0 ... SIZE_EC_PRIVATE_KEY - 1] = 0x00},
    {[0 ... SIZE_EC_POINT_COMPRESSED - 1] = 0x00}
};

// The position of the yet-to-be-verified byte.
static uint8_t _challenge_byte_position = CHALLENGE_BYTE_POSITION_START;

// The position of the current 2 bit inside the yet-to-be-verified byte.
// Valid values are 1 to 4.
static uint8_t _challenge_bit_position = CHALLENGE_BIT_POSITION_START;

// Enforced order:
//      1 hash_pubkey (can be called anytime to start over)
//      2 pubkey (cannot be called twice)
//      3 challenge (can be called repeatedly)
//      - An abort command requires starting over
typedef enum {
    CMD_HASH_PUBKEY,
    CMD_PUBKEY,
    CMD_CHALLENGE,
    CMD_ABORTED,
} _cmd_order_t;
static uint8_t _last_command = CMD_ABORTED;

// The cached shared secret, set after a successful pubkey command.
// It is erased:
//      - Immediately after written to eeprom
//      - After an abort command
//      - On a command error
static uint8_t _shared_secret[SIZE_ECDH_SHARED_SECRET] = {0};
#ifdef TESTING
static uint8_t _test_shared_secret[SIZE_ECDH_SHARED_SECRET] = {0};
uint8_t *test_shared_secret_report(void)
{
    return _test_shared_secret;
}
#endif


/**
 * Clear static variables
 */
static void _clear_static_variables(void)
{
#ifdef TESTING
    utils_zero(_test_shared_secret, SIZE_ECDH_SHARED_SECRET);
#endif
    utils_zero(_shared_secret, SIZE_ECDH_SHARED_SECRET);
    utils_zero(_input_hash_pubkey, SHA256_DIGEST_LENGTH);
    utils_zero(&_keypair, sizeof(_keypair_t));
    utils_clear_buffers();
}


/**
 * Generates a new EC key pair on the SECP256k1 curve and stores it in the address given as a
 * parameter.
 */
static int _generate_key(_keypair_t *keypair)
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
static void _hash_pubkey_command(const char *pair_hash_pubkey)
{
    if (strlens(pair_hash_pubkey) != SIZE_SHA256_HEX) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_KEY_HASH_ECDH_LEN);
        goto cleanup;
    }

    int status = touch_button_press(TOUCH_LONG_PAIR);
    if (status != DBB_TOUCHED) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, status);
        goto cleanup;
    }

    _challenge_bit_position = CHALLENGE_BIT_POSITION_START;
    _challenge_byte_position = CHALLENGE_BYTE_POSITION_START;
    int ret = _generate_key(&_keypair);
    if (ret != DBB_OK) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, ret);
        goto cleanup;
    }

    char msg[256];
    uint8_t hash_pubkey[SHA256_DIGEST_LENGTH];
    sha256_Raw(_keypair.public_key, sizeof(_keypair.public_key), hash_pubkey);
    snprintf(msg, sizeof(msg), "{\"%s\":\"%s\"}",
             cmd_str(CMD_hash_pubkey), utils_uint8_to_hex(hash_pubkey, sizeof(hash_pubkey)));

    _last_command = CMD_HASH_PUBKEY;
    memcpy(_input_hash_pubkey, utils_hex_to_uint8(pair_hash_pubkey), SHA256_DIGEST_LENGTH);
    commander_clear_report();
    commander_fill_report(cmd_str(CMD_ecdh), msg, DBB_JSON_ARRAY);
    return;

cleanup:
    _last_command = CMD_ABORTED;
    _clear_static_variables();
}


/**
 * Process the { "ecdh" : { "pubkey" : "..." } } command.
 * First, we check whether the provided public key is the one to which the pairing partner
 * committed to in a previous request (hash_pubkey).
 * Then, we create the ECDH shared secret and store it in the eeprom.
 * Lastly, the hash of the pairing partner's public key and keypair for generating the shared
 * secret is reset.
 */
static void _pubkey_command(const char *pair_pubkey)
{
    if (_last_command != CMD_HASH_PUBKEY) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_IO_CMD_ORDER);
        goto cleanup;
    }
    _last_command = CMD_PUBKEY;

    // 66 bytes because it's the hex representation of a compressed EC public key.
    if (strlens(pair_pubkey) != SIZE_EC_POINT_COMPRESSED_HEX) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_KEY_ECDH_LEN);
        goto cleanup;
    }

    uint8_t pair_pubkey_bytes[SIZE_EC_POINT_COMPRESSED];
    memcpy(pair_pubkey_bytes, utils_hex_to_uint8(pair_pubkey), SIZE_EC_POINT_COMPRESSED);

    // Point-at-infinity not allowed
    if (MEMEQ(_zero_32, pair_pubkey_bytes + 1, SHA256_DIGEST_LENGTH)) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_TFA_HASH_MATCH);
        goto cleanup;
    }

    // Check if hashed pubkey was provided
    if (MEMEQ(_zero_32, _input_hash_pubkey, SHA256_DIGEST_LENGTH)) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_TFA_HASH_MATCH);
        goto cleanup;
    }

    uint8_t h[SHA256_DIGEST_LENGTH];
    sha256_Raw(pair_pubkey_bytes, SIZE_EC_POINT_COMPRESSED, h);

    // Check if the pubkey matches the provided hashed pubkey
    if (!MEMEQ(h, _input_hash_pubkey, SHA256_DIGEST_LENGTH)) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_TFA_HASH_MATCH);
        goto cleanup;
    }

    if (bitcoin_ecc.ecc_ecdh(pair_pubkey_bytes, _keypair.private_key, _shared_secret,
                             ECC_SECP256k1)) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_KEY_ECDH);
        goto cleanup;
    }
#ifdef TESTING
    memcpy(_test_shared_secret, _shared_secret, SIZE_ECDH_SHARED_SECRET);
#endif

    char msg[256];
    snprintf(msg, sizeof(msg), "{\"%s\":\"%s\"}",
             cmd_str(CMD_pubkey), utils_uint8_to_hex(_keypair.public_key,
                     sizeof(_keypair.public_key)));

    commander_fill_report(cmd_str(CMD_ecdh), msg, DBB_JSON_OBJECT);
    return;

cleanup:
    _last_command = CMD_ABORTED;
    _clear_static_variables();
}

/**
 * Challenge the pairing by blinking the LED to verify the shared secret.
 * When this command is called, the LED blinks 1 - 4 times to communicate the value of the
 * 2 bits at the current position of the shared secret.
 * The position is advanced afterwards.
 */
static void _challenge_command(void)
{
    if (_last_command != CMD_PUBKEY && _last_command != CMD_CHALLENGE) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_IO_CMD_ORDER);
        goto cleanup;
    }

    _last_command = CMD_CHALLENGE;

    // Save the shared secret to eeprom only after the challenge command has been
    // repeated CHALLENGE_MIN_BLINK_SETS times. Then erase the cached shared secret, now
    // that it is 'accepted'. The challenge is a hash of a secret and not a secret itself.
    static uint8_t challenge[SHA256_DIGEST_LENGTH] = {0};
    if (_challenge_bit_position == CHALLENGE_BIT_POSITION_START &&
            _challenge_byte_position == CHALLENGE_BYTE_POSITION_START) {
        uint8_t encryption_and_authentication_key[SHA512_DIGEST_LENGTH] = {0};
        sha512_Raw(_shared_secret, SIZE_ECDH_SHARED_SECRET, encryption_and_authentication_key);
        sha256_Raw(encryption_and_authentication_key, SHA512_DIGEST_LENGTH, challenge);
        utils_zero(encryption_and_authentication_key, SHA512_DIGEST_LENGTH);
    }
    if (_challenge_bit_position == CHALLENGE_MIN_SETS_BIT_VALUE &&
            _challenge_byte_position == CHALLENGE_MIN_SETS_BYTE_VALUE) {
        int ret = memory_write_tfa_shared_secret(_shared_secret);
        _clear_static_variables();
        if (ret != DBB_OK) {
            commander_fill_report(cmd_str(CMD_ecdh), NULL, ret);
            goto cleanup;
        }
    }

    uint8_t two_bit = (challenge[_challenge_byte_position] >>
                       (SIZE_BYTE - 2 * _challenge_bit_position)) & 3;

    _challenge_bit_position = (_challenge_bit_position + 1) % (CHALLENGE_BIT_POSITION_MAX +
                              1);
    if (_challenge_bit_position == 0) {
        _challenge_byte_position = (_challenge_byte_position + 1) % SIZE_ECDH_SHARED_SECRET;
        _challenge_bit_position = CHALLENGE_BIT_POSITION_START;
    }

    led_2FA_pairing_code(two_bit + 1);

    commander_fill_report(cmd_str(CMD_ecdh), attr_str(ATTR_success), DBB_JSON_STRING);
    return;

cleanup:
    _last_command = CMD_ABORTED;
    _clear_static_variables();
}


/**
 * Aborts the pairing process and thereby resets the positions for blinking.
 */
static void _abort(void)
{
    _clear_static_variables();
    _last_command = CMD_ABORTED;
    _challenge_bit_position = CHALLENGE_BIT_POSITION_START;
    _challenge_byte_position = CHALLENGE_BYTE_POSITION_START;
    commander_fill_report(cmd_str(CMD_ecdh), attr_str(ATTR_aborted), DBB_JSON_STRING);
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
            _hash_pubkey_command(pair_hash_pubkey);
            return;
        } else if (strlens(pair_pubkey)) {
            _pubkey_command(pair_pubkey);
            return;
        } else if (YAJL_IS_TRUE(pair_challenge)) {
            _challenge_command();
            return;
        } else if (YAJL_IS_TRUE(pair_abort)) {
            _abort();
            return;
        }
    }

    _abort();
    commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_IO_INVALID_CMD);
}
