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


uint8_t *wallet_get_master(void)
{
    if (HIDDEN) {
        return memory_master_hww_chaincode(NULL);
    } else {
        return memory_master_hww(NULL);
    }
}


uint8_t *wallet_get_chaincode(void)
{
    if (HIDDEN) {
        return memory_master_hww(NULL);
    } else {
        return memory_master_hww_chaincode(NULL);
    }
}


int wallet_seeded(void)
{
    if (!memcmp(memory_master_hww(NULL), MEM_PAGE_ERASE, 32)  ||
            !memcmp(memory_master_hww_chaincode(NULL), MEM_PAGE_ERASE, 32)) {
        return DBB_ERROR;
    } else {
        return DBB_OK;
    }
}


static void wallet_report_xpriv(const char *keypath, char *xpriv)
{
    HDNode node;
    if (wallet_seeded() == DBB_OK) {
        if (wallet_generate_key(&node, keypath, wallet_get_master(),
                                wallet_get_chaincode()) == DBB_OK) {
            hdnode_serialize_private(&node, xpriv, 112);
        }
    }
    utils_zero(&node, sizeof(HDNode));
}


int wallet_generate_master(const char *passphrase, const char *entropy_in)
{
    int ret = DBB_OK;
    uint8_t entropy[MEM_PAGE_LEN];
    HDNode node;

    if (strlens(entropy_in) != MEM_PAGE_LEN * 2) {
        return DBB_ERROR;
    }

    ret = wallet_generate_node(passphrase, entropy_in, &node);
    if (ret != DBB_OK) {
        goto exit;
    }

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


int wallet_generate_key(HDNode *node, const char *keypath, const uint8_t *privkeymaster,
                        const uint8_t *chaincode)
{
    static char delim[] = "/";
    static char prime[] = "phH\'";
    static char digits[] = "0123456789";
    uint64_t idx = 0;
    char *pch, *kp = malloc(strlens(keypath) + 1);

    if (!kp) {
        return DBB_ERROR_MEM;
    }

    if (strlens(keypath) < strlens("m/")) {
        goto err;
    }

    memset(kp, 0, strlens(keypath) + 1);
    memcpy(kp, keypath, strlens(keypath));

    if (kp[0] != 'm' || kp[1] != '/') {
        goto err;
    }

    node->depth = 0;
    node->child_num = 0;
    node->fingerprint = 0;
    memcpy(node->chain_code, chaincode, 32);
    memcpy(node->private_key, privkeymaster, 32);
    hdnode_fill_public_key(node);

    pch = strtok(kp + 2, delim);
    while (pch != NULL) {
        size_t i = 0;
        int prm = 0;
        for ( ; i < strlens(pch); i++) {
            if (strchr(prime, pch[i])) {
                if (i != strlens(pch) - 1) {
                    goto err;
                }
                prm = 1;
            } else if (!strchr(digits, pch[i])) {
                goto err;
            }
        }

        idx = strtoull(pch, NULL, 10);
        if (idx > UINT32_MAX) {
            goto err;
        }

        if (prm) {
            if (hdnode_private_ckd_prime(node, idx) != DBB_OK) {
                goto err;
            }
        } else {
            if (hdnode_private_ckd(node, idx) != DBB_OK) {
                goto err;
            }
        }
        pch = strtok(NULL, delim);
    }
    free(kp);
    return DBB_OK;

err:
    free(kp);
    return DBB_ERROR;
}


int wallet_generate_node(const char *passphrase, const char *entropy, HDNode *node)
{
    int ret;
    uint8_t seed[PBKDF2_HMACLEN];
    char salt[8 + strlens(passphrase) + 1];
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


void wallet_report_xpub(const char *keypath, char *xpub)
{
    HDNode node;
    if (wallet_seeded() == DBB_OK) {
        if (wallet_generate_key(&node, keypath, wallet_get_master(),
                                wallet_get_chaincode()) == DBB_OK) {
            hdnode_serialize_public(&node, xpub, 112);
        }
    }
    utils_zero(&node, sizeof(HDNode));
}


void wallet_report_id(char *id)
{
    uint8_t h[32];
    char xpub[112] = {0};
    wallet_report_xpub("m/", xpub);
    sha256_Raw((uint8_t *)xpub, 112, h);
    memcpy(id, utils_uint8_to_hex(h, 32), 64);
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
                            wallet_get_chaincode()) != DBB_OK) {
        commander_clear_report();
        commander_fill_report(cmd_str(CMD_checkpub), NULL, DBB_ERR_KEY_CHILD);
        goto err;
    }

    bitcoin_ecc.ecc_get_public_key33(node.private_key, pub_key, ECC_SECP256k1);

    utils_zero(&node, sizeof(HDNode));
    if (strncmp(pubkey, utils_uint8_to_hex(pub_key, 33), 66)) {
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
                            wallet_get_chaincode()) != DBB_OK) {
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

