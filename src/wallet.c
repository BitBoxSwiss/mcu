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
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

#include "commander.h"
#include "ripemd160.h"
#include "wallet.h"
#include "base58.h"
#include "pbkdf2.h"
#include "utils.h"
#include "flags.h"
#include "sha2.h"
#include "ecc.h"


extern const uint8_t MEM_PAGE_ERASE[MEM_PAGE_LEN];
extern const uint8_t MEM_PAGE_ERASE_FE[MEM_PAGE_LEN];
extern const uint16_t MEM_PAGE_ERASE_2X[MEM_PAGE_LEN];


static uint8_t HIDDEN = 0;


void wallet_set_hidden(int hide)
{
    HIDDEN = hide;
}


int wallet_is_hidden(void)
{
    return HIDDEN;
}


int wallet_is_locked(void)
{
    return HIDDEN || !memory_read_unlocked();
}

int wallet_is_paired(void)
{
    return wallet_is_locked() || !(memory_report_ext_flags() & MEM_EXT_MASK_NOTPAIRED);
}

uint8_t *wallet_get_master(void)
{
    uint8_t *std = memory_master_hww(NULL);
    uint8_t *hdn = memory_hidden_hww(NULL);
    return (HIDDEN ? hdn : std);
}


uint8_t *wallet_get_chaincode(void)
{
    uint8_t *std = memory_master_hww_chaincode(NULL);
    uint8_t *hdn = memory_hidden_hww_chaincode(NULL);
    return (HIDDEN ? hdn : std);
}

int wallet_seeded(void)
{
    if (MEMEQ(memory_master_hww(NULL), MEM_PAGE_ERASE, 32)  ||
            MEMEQ(memory_master_hww_chaincode(NULL), MEM_PAGE_ERASE, 32) ||
            MEMEQ(memory_master_hww_entropy(NULL), MEM_PAGE_ERASE, 32)) {
        return DBB_ERROR;
    } else {
        return DBB_OK;
    }
}

int wallet_erased(void)
{
    if (!MEMEQ(memory_master_hww(NULL), MEM_PAGE_ERASE, 32)  ||
            !MEMEQ(memory_master_hww_chaincode(NULL), MEM_PAGE_ERASE, 32)  ||
            !MEMEQ(memory_hidden_hww(NULL), MEM_PAGE_ERASE_FE, 32)  ||
            !MEMEQ(memory_hidden_hww_chaincode(NULL), MEM_PAGE_ERASE_FE, 32)  ||
            !MEMEQ(memory_master_hww_entropy(NULL), MEM_PAGE_ERASE, 32)) {
        return DBB_ERROR;
    } else {
        return DBB_OK;
    }
}

int wallet_create(const char *passphrase, const char *entropy_in)
{
    int ret = DBB_OK;
    uint8_t entropy[MEM_PAGE_LEN];
    HDNode node;

    ret = wallet_generate_node(passphrase, entropy_in, &node);
    if (ret != DBB_OK) {
        goto exit;
    }

    memory_erase_hww_seed();
    memcpy(entropy, utils_hex_to_uint8(entropy_in), sizeof(entropy));
    memory_master_hww(node.private_key);
    memory_master_hww_chaincode(node.chain_code);
    memory_master_hww_entropy(entropy);

    ret = wallet_seeded();
    if (ret != DBB_OK) {
        ret = DBB_ERROR_MEM;
    }

exit:
    utils_zero(&node, sizeof(HDNode));
    utils_zero(entropy, sizeof(entropy));
    return ret;
}

int wallet_check_keypath_prefix(const uint32_t
                                keypath0[MAX_PARSE_KEYPATH_LEVEL],
                                const uint32_t keypath1[MAX_PARSE_KEYPATH_LEVEL],
                                const uint32_t depth)
{
    if (depth < MIN_WALLET_DEPTH || !MEMEQ(keypath0, keypath1, (depth - 2) * sizeof(uint32_t))) {
        return DBB_ERROR;
    }
    return DBB_OK;
}


int wallet_check_change_keypath(const uint32_t utxo[MAX_PARSE_KEYPATH_LEVEL],
                                const uint32_t change[MAX_PARSE_KEYPATH_LEVEL],
                                const uint32_t change_depth)
{
    // Check that the depth is at least 2
    if (change_depth < MIN_WALLET_DEPTH) {
        return DBB_ERROR;
    }

    // Check the change keypath's change level
    if (change[change_depth - 2] != 1) {
        return DBB_ERROR;
    }
    // Check that the change keypath address level is within range
    if (change[change_depth - 1] > BIP44_ADDRESS_MAX) {
        return DBB_ERROR;
    }
    // Check that purpose, coin type, and account indices are the same
    return wallet_check_keypath_prefix(utxo, change, change_depth);
}


int wallet_parse_bip44_keypath(HDNode *node,
                               uint32_t keypath_array[MAX_PARSE_KEYPATH_LEVEL],
                               uint32_t *depth, const char *keypath, const uint8_t *privkeymaster,
                               const uint8_t *chaincodemaster)
{
    static char delim[] = "/";
    static char prime[] = "phH\'";
    static char digits[] = "0123456789";
    uint64_t idx = 0;
    *depth = 0;

    char *kp = strdup(keypath);
    if (!kp) {
        return DBB_ERROR_MEM;
    }

    if (strlens(keypath) < strlens("m/")) {
        goto err;
    }

    if (kp[0] != 'm' || kp[1] != '/') {
        goto err;
    }

    if (node && privkeymaster && chaincodemaster) {
        node->depth = 0;
        node->child_num = 0;
        node->fingerprint = 0;
        memcpy(node->chain_code, chaincodemaster, 32);
        memcpy(node->private_key, privkeymaster, 32);
        hdnode_fill_public_key(node);
    }

    char *pch = strtok(kp + 2, delim);
    if (pch == NULL) {
        goto err;
    }
    uint8_t path_level = 0;
    bool has_prime = false;
    while (pch != NULL) {
        size_t i = 0;
        bool is_prime = false;
        size_t pch_len = strlens(pch);
        for ( ; i < pch_len; i++) {
            if (strchr(prime, pch[i])) {
                if (i != pch_len - 1) {
                    goto err;
                }
                is_prime = true;
                has_prime = true;
            } else if (!strchr(digits, pch[i])) {
                goto err;
            }
        }
        if (is_prime && pch_len == 1) {
            goto err;
        }
        idx = strtoull(pch, NULL, 10);
        if (idx >= BIP44_PRIME) {
            goto err;
        }

        if (node && privkeymaster && chaincodemaster) {
            if (is_prime) {
                if (hdnode_private_ckd_prime(node, idx) != DBB_OK) {
                    goto err;
                }
            } else {
                if (hdnode_private_ckd(node, idx) != DBB_OK) {
                    goto err;
                }
            }
        }

        if (path_level < MAX_PARSE_KEYPATH_LEVEL) {
            keypath_array[path_level] = idx + (is_prime ? BIP44_PRIME : 0);
        }

        pch = strtok(NULL, delim);
        path_level++;
        *depth = path_level;
    }
    if (!has_prime) {
        goto err;
    }
    free(kp);
    return DBB_OK;

err:
    free(kp);
    return DBB_ERROR;
}


/*
 Returns DBB_OK if successful and keypath is whitelisted
 Returns DBB_WARN_KEYPATH if successful but keypath is not whitelisted
 Returns DBB_ERROR if could not generate a key
*/
int wallet_generate_key(HDNode *node, const char *keypath, const uint8_t *privkeymaster,
                        const uint8_t *chaincodemaster)
{
    uint32_t keypath_array[MAX_PARSE_KEYPATH_LEVEL] = {0};
    uint32_t depth = 0;
    if (wallet_parse_bip44_keypath(node, keypath_array, &depth, keypath,
                                   privkeymaster, chaincodemaster) != DBB_OK) {
        return DBB_ERROR;
    }

    // Check if the keypath is whitelisted
    uint32_t idx;
    idx = keypath_array[BIP44_LEVEL_PURPOSE];
    if (idx != (BIP44_PURPOSE_P2PKH + (BIP44_PURPOSE_HARDENED ? BIP44_PRIME : 0)) &&
            idx != (BIP44_PURPOSE_P2WPKH + (BIP44_PURPOSE_HARDENED ? BIP44_PRIME : 0)) &&
            idx != (BIP44_PURPOSE_P2WPKH_P2SH + (BIP44_PURPOSE_HARDENED ? BIP44_PRIME : 0))) {
        return DBB_WARN_KEYPATH;
    }

    idx = keypath_array[BIP44_LEVEL_COIN_TYPE];
    if (idx != (BIP44_COIN_TYPE_BTC + (BIP44_COIN_TYPE_HARDENED ? BIP44_PRIME : 0)) &&
            idx != (BIP44_COIN_TYPE_LTC + (BIP44_COIN_TYPE_HARDENED ? BIP44_PRIME : 0)) &&
            idx != (BIP44_COIN_TYPE_TESTNET + (BIP44_COIN_TYPE_HARDENED ? BIP44_PRIME : 0))) {
        return DBB_WARN_KEYPATH;
    }

    idx = keypath_array[BIP44_LEVEL_ACCOUNT];
    if (idx > (BIP44_ACCOUNT_MAX + (BIP44_ACCOUNT_HARDENED ? BIP44_PRIME : 0)) ||
            idx < (BIP44_ACCOUNT_HARDENED ? BIP44_PRIME : 0)) {
        return DBB_WARN_KEYPATH;
    }

    idx = keypath_array[BIP44_LEVEL_CHANGE];
    if (idx > BIP44_CHANGE_MAX) {
        return DBB_WARN_KEYPATH;
    }

    idx = keypath_array[BIP44_LEVEL_ADDRESS];
    if (idx > BIP44_ADDRESS_MAX) {
        return DBB_WARN_KEYPATH;
    }

    if (node->depth != BIP44_KEYPATH_ADDRESS_DEPTH) {
        return DBB_WARN_KEYPATH;
    }

    return DBB_OK;
}


int wallet_generate_node(const char *passphrase, const char *entropy, HDNode *node)
{
    int ret;
    uint8_t seed[PBKDF2_HMACLEN];
    char salt[8 + strlens(passphrase) + 1];

    if (strlens(entropy) != MEM_PAGE_LEN * 2) {
        return DBB_ERROR;
    }

    snprintf(salt, sizeof(salt), "%s%s", "mnemonic", passphrase);
    pbkdf2_hmac_sha512((const uint8_t *)entropy, strlens(entropy), salt, seed,
                       sizeof(seed));

    if (hdnode_from_seed(seed, sizeof(seed), node) == DBB_ERROR) {
        ret = DBB_ERROR;
    } else {
        ret = DBB_OK;
    }

    utils_zero(seed, sizeof(seed));
    utils_zero(salt, sizeof(salt));
    return ret;
}


int wallet_report_xpub(const char *keypath, char *xpub)
{
    HDNode node;
    int ret = DBB_ERROR;
    if (wallet_seeded() == DBB_OK) {
        ret = wallet_generate_key(&node, keypath, wallet_get_master(), wallet_get_chaincode());
        if (ret != DBB_ERROR) {
            hdnode_serialize_public(&node, xpub, 112);
        }
    }
    utils_zero(&node, sizeof(HDNode));
    return ret;
}


void wallet_report_id(char *id)
{
    uint8_t h[32];
    char xpub[112] = {0};
    wallet_report_xpub("m/151'/144'", xpub);// ascii 'i' / 'd'
    if (xpub[0]) {
        sha256_Raw((uint8_t *)xpub, 112, h);
        sha256_Raw(h, 32, h);
        memcpy(id, utils_uint8_to_hex(h, 32), 64);
    }
}


int wallet_check_pubkey(const char *pubkey, const char *keypath)
{
    uint8_t pub_key[33];
    HDNode node;

    if (strlens(pubkey) != 66) {
        commander_clear_report();
        commander_fill_report(cmd_str(CMD_checkpub), NULL, DBB_ERR_SIGN_PUBKEY_LEN);
        goto err;
    }

    if (wallet_seeded() != DBB_OK) {
        commander_clear_report();
        commander_fill_report(cmd_str(CMD_checkpub), NULL, DBB_ERR_KEY_MASTER);
        goto err;
    }

    if (wallet_generate_key(&node, keypath, wallet_get_master(),
                            wallet_get_chaincode()) == DBB_ERROR) {
        commander_clear_report();
        commander_fill_report(cmd_str(CMD_checkpub), NULL, DBB_ERR_KEY_CHILD);
        goto err;
    }

    bitcoin_ecc.ecc_get_public_key33(node.private_key, pub_key, ECC_SECP256k1);

    utils_zero(&node, sizeof(HDNode));
    if (!STREQ(pubkey, utils_uint8_to_hex(pub_key, 33))) {
        return DBB_KEY_ABSENT;
    } else {
        return DBB_KEY_PRESENT;
    }

err:
    utils_zero(&node, sizeof(HDNode));
    return DBB_ERROR;
}


int wallet_sign(const char *message, const char *keypath)
{
    uint8_t data[32];
    uint8_t sig[64];
    uint8_t recid = 0xEE;// Set default value to give an error when trying to recover
    HDNode node;

    if (strlens(message) != (32 * 2)) {
        commander_clear_report();
        commander_fill_report(cmd_str(CMD_sign), NULL, DBB_ERR_SIGN_HASH_LEN);
        goto err;
    }

    if (wallet_seeded() != DBB_OK) {
        commander_clear_report();
        commander_fill_report(cmd_str(CMD_sign), NULL, DBB_ERR_KEY_MASTER);
        goto err;
    }

    if (wallet_generate_key(&node, keypath, wallet_get_master(),
                            wallet_get_chaincode()) == DBB_ERROR) {
        commander_clear_report();
        commander_fill_report(cmd_str(CMD_sign), NULL, DBB_ERR_KEY_CHILD);
        goto err;
    }

    memcpy(data, utils_hex_to_uint8(message), 32);

    if (bitcoin_ecc.ecc_sign_digest(node.private_key, data, sig, &recid, ECC_SECP256k1)) {
        commander_clear_report();
        commander_fill_report(cmd_str(CMD_sign), NULL, DBB_ERR_SIGN_ECCLIB);
        goto err;
    }

    utils_zero(&node, sizeof(HDNode));
    return commander_fill_signature_array(sig, recid);

err:
    utils_zero(&node, sizeof(HDNode));
    return DBB_ERROR;
}


// -- bitcoin formats -- //
// from: github.com/trezor/trezor-crypto

void wallet_get_pubkeyhash(const uint8_t *pub_key, uint8_t *pubkeyhash)
{
    uint8_t h[32];
    if (pub_key[0] == 0x04) {        // uncompressed format
        sha256_Raw(pub_key, 65, h);
    } else if (pub_key[0] == 0x00) { // point at infinity
        sha256_Raw(pub_key, 1, h);
    } else {
        sha256_Raw(pub_key, 33, h);  // expecting compressed format
    }
    ripemd160(h, 32, pubkeyhash);
}

void wallet_get_address_raw(const uint8_t *pub_key, uint8_t version, uint8_t *addr_raw)
{
    addr_raw[0] = version;
    wallet_get_pubkeyhash(pub_key, addr_raw + 1);
}

void wallet_get_address(const uint8_t *pub_key, uint8_t version, char *addr, int addrsize)
{
    uint8_t raw[21];
    wallet_get_address_raw(pub_key, version, raw);
    base58_encode_check(raw, 21, addr, addrsize);
}

void wallet_get_wif(const uint8_t *priv_key, uint8_t version, char *wif, int wifsize)
{
    uint8_t data[34];
    data[0] = version;
    memcpy(data + 1, priv_key, 32);
    data[33] = 0x01;
    base58_encode_check(data, 34, wif, wifsize);
}
