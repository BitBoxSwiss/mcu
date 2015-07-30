/*

 The MIT License (MIT)

 Copyright (c) 2015 Douglas J. Bakkum

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

/* Some functions adapted from the Trezor crypto library. */


#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#include "commander.h"
#include "ripemd160.h"
#include "wallet.h"
#include "memory.h"
#include "random.h"
#include "base64.h"
#include "base58.h"
#include "pbkdf2.h"
#include "utils.h"
#include "bip32.h"
#include "flags.h"
#include "hmac.h"
#include "sha2.h"
#include "uECC.h"
#include "led.h"

#include "bip39_english.h"

extern const uint8_t MEM_PAGE_ERASE[MEM_PAGE_LEN];
extern const uint16_t MEM_PAGE_ERASE_2X[MEM_PAGE_LEN];

static char mnemonic[(BIP39_MAX_WORD_LEN + 1) * MAX_SEED_WORDS + 1];
static uint16_t seed_index[MAX_SEED_WORDS];
static uint8_t seed[64];
static uint8_t rand_data_32[32];


// Avoid leaving secrets in RAM
static void clear_static_variables(void)
{
    memset(seed, 0, sizeof(seed));
    memset(mnemonic, 0, sizeof(mnemonic));
    memset(seed_index, 0, sizeof(seed_index));
    memset(rand_data_32, 0, sizeof(rand_data_32));
}


int wallet_split_seed(char **seed_words, const char *message)
{
    int i = 0;
    static char msg[(BIP39_MAX_WORD_LEN + 1) * MAX_SEED_WORDS + 1];

    memset(msg, 0, sizeof(msg));
    snprintf(msg, sizeof(msg), "%s", message);
    seed_words[i] = strtok(msg, " ,");
    for (i = 0; seed_words[i] != NULL; i++) {
        if (i + 1 >= MAX_SEED_WORDS) {
            break;
        }
        seed_words[i + 1] = strtok(NULL, " ,");
    }
    return i;
}


const char **wallet_mnemonic_wordlist(void)
{
    return wordlist;
}


uint16_t *wallet_index_from_mnemonic(const char *mnemo)
{
    int i, j, k, seed_words_n;
    char *seed_word[MAX_SEED_WORDS] = {NULL};
    memset(seed_index, 0, sizeof(seed_index));
    seed_words_n = wallet_split_seed(seed_word, mnemo);

    k = 0;
    for (i = 0; i < seed_words_n; i++) {
        if (i >= MAX_SEED_WORDS) {
            break;
        }
        for (j = 0; wordlist[j]; j++) {
            if (strcmp(seed_word[i], wordlist[j]) == 0) { // word found
                seed_index[k++] = j + 1; // offset of 1
                break;
            }
        }
    }
    return seed_index;
}


char *wallet_mnemonic_from_index(const uint16_t *idx)
{
    if (!memcmp(idx, MEM_PAGE_ERASE_2X, 64)) {
        return NULL;
    }
    int i;
    memset(mnemonic, 0, sizeof(mnemonic));
    for (i = 0; idx[i]; i++) {
        if (i >= MAX_SEED_WORDS || idx[i] > BIP39_NUM_WORDS) {
            return NULL;
        }
        strncat(mnemonic, wordlist[idx[i] - 1], BIP39_MAX_WORD_LEN);
        strncat(mnemonic, " ", 1);
    }

    if (i == 0 || strlens(mnemonic) < 1) {
        return NULL;
    }

    mnemonic[strlens(mnemonic) - 1] = '\0';
    return mnemonic;
}


int wallet_master_from_mnemonic(char *mnemo, int m_len, const char *salt, int s_len)
{
    int ret = STATUS_SUCCESS;
    HDNode node;

    clear_static_variables();

    if (mnemo == NULL) {
        if (random_bytes(rand_data_32, 32, 1) == STATUS_ERROR) {
            ret = STATUS_ERROR_MEM;
            goto exit;
        }
        mnemo = wallet_mnemonic_from_data(rand_data_32, 32);
        memcpy(mnemonic, mnemo, strlens(mnemo));
    } else {
        if ((size_t)m_len > sizeof(mnemonic)) {
            ret = STATUS_ERROR;
            goto exit;
        }
        snprintf(mnemonic, sizeof(mnemonic), "%.*s", m_len, mnemo);
    }

    if (wallet_mnemonic_check(mnemonic) == STATUS_ERROR) {
        ret = STATUS_ERROR;
        goto exit;
    }

    if (salt == NULL || s_len == 0) {
        wallet_mnemonic_to_seed(mnemonic, NULL, seed, 0);
    } else {
        wallet_mnemonic_to_seed(mnemonic, salt, seed, 0);
    }

    if (hdnode_from_seed(seed, sizeof(seed), &node) == STATUS_ERROR) {
        ret = STATUS_ERROR;
        goto exit;
    }

    if (!memcmp(memory_master(node.private_key), MEM_PAGE_ERASE, 32)  ||
            !memcmp(memory_chaincode(node.chain_code), MEM_PAGE_ERASE, 32) ||
            !memcmp(memory_mnemonic(wallet_index_from_mnemonic(mnemonic)), MEM_PAGE_ERASE_2X, 64)) {
        ret = STATUS_ERROR_MEM;
        goto exit;
    } else {
        ret = STATUS_SUCCESS;
        goto exit;
    }

exit:
    memset(&node, 0, sizeof(HDNode));
    clear_static_variables();
    return ret;
}


int wallet_generate_key(HDNode *node, const char *keypath, int keypath_len,
                        const uint8_t *privkeymaster, const uint8_t *chaincode)
{
    unsigned long idx = 0;
    char *pch, *kp = malloc(keypath_len + 1);

    if (!kp) {
        return STATUS_ERROR_MEM;
    }

    memcpy(kp, keypath, keypath_len);
    kp[keypath_len] = '\0';

    node->depth = 0;
    node->child_num = 0;
    node->fingerprint = 0;
    memcpy(node->chain_code, chaincode, 32);
    memcpy(node->private_key, privkeymaster, 32);
    hdnode_fill_public_key(node);

    pch = strtok(kp, " /,m\\");
    while (pch != NULL) {
        sscanf(pch, "%lu", &idx);
        if (pch[strlens(pch) - 1] == '\'' ||
                pch[strlens(pch) - 1] == 'p'  ||
                pch[strlens(pch) - 1] == 'h'  ||
                pch[strlens(pch) - 1] == 'H') {
            if (hdnode_private_ckd_prime(node, idx) != STATUS_SUCCESS) {
                goto err;
            }
        } else {
            if (hdnode_private_ckd(node, idx) != STATUS_SUCCESS) {
                goto err;
            }
        }
        pch = strtok(NULL, " /,m\\");
    }
    free(kp);
    return STATUS_SUCCESS;

err:
    free(kp);
    return STATUS_ERROR;
}


void wallet_report_xpub(const char *keypath, int keypath_len, char *xpub)
{
    uint8_t *priv_key_master = memory_master(NULL);
    uint8_t *chain_code = memory_chaincode(NULL);
    HDNode node;

    if (memcmp(priv_key_master, MEM_PAGE_ERASE, 32) &&
            memcmp(chain_code, MEM_PAGE_ERASE, 32)) {
        if (wallet_generate_key(&node, keypath, keypath_len, priv_key_master,
                                chain_code) == STATUS_SUCCESS) {
            hdnode_serialize_public(&node, xpub, 112);
        }
    }
    memset(&node, 0, sizeof(HDNode));
    clear_static_variables();
}


int wallet_sign(const char *message, int msg_len, const char *keypath, int keypath_len,
                int to_hash)
{
    uint8_t data[32];
    uint8_t sig[64];
    uint8_t *priv_key_master = memory_master(NULL);
    uint8_t *chain_code = memory_chaincode(NULL);
    uint8_t pub_key[33];
    HDNode node;

    if (!to_hash && msg_len != (32 * 2)) {
        commander_fill_report("sign", FLAG_ERR_SIGN_LEN, STATUS_ERROR);
        goto err;
    }

    if (!memcmp(priv_key_master, MEM_PAGE_ERASE, 32) ||
            !memcmp(chain_code, MEM_PAGE_ERASE, 32)) {
        commander_fill_report("sign", FLAG_ERR_BIP32_MISSING, STATUS_ERROR);
        goto err;
    }

    if (wallet_generate_key(&node, keypath, keypath_len, priv_key_master,
                            chain_code) != STATUS_SUCCESS) {
        commander_fill_report("sign", FLAG_ERR_KEY_GEN, STATUS_ERROR);
        goto err;
    }

    int ret = 0;
    if (to_hash) {
        ret = uECC_sign_double(node.private_key, utils_hex_to_uint8(message), msg_len / 2, sig);
    } else {
        memcpy(data, utils_hex_to_uint8(message), 32);
        ret = uECC_sign_digest(node.private_key, data, sig);
    }
    if (ret) {
        commander_fill_report("sign", FLAG_ERR_SIGN, STATUS_ERROR);
        return STATUS_ERROR;
    }

    uECC_get_public_key33(node.private_key, pub_key);
    commander_fill_report_signature(sig, pub_key);
    memset(&node, 0, sizeof(HDNode));
    clear_static_variables();
    return STATUS_SUCCESS;

err:
    memset(&node, 0, sizeof(HDNode));
    clear_static_variables();
    return STATUS_ERROR;
}


char *wallet_mnemonic_from_data(const uint8_t *data, int len)
{
    if (len % 4 || len < 16 || len > 32) {
        return 0;
    }

    uint8_t bits[32 + 1];

    sha256_Raw(data, len, bits);
    bits[len] = bits[0];
    memcpy(bits, data, len);

    int mlen = len * 3 / 4;
    static char mnemo[24 * 10];

    int i, j;
    char *p = mnemo;
    for (i = 0; i < mlen; i++) {
        int idx = 0;
        for (j = 0; j < 11; j++) {
            idx <<= 1;
            idx += (bits[(i * 11 + j) / 8] & (1 << (7 - ((i * 11 + j) % 8)))) > 0;
        }
        strcpy(p, wordlist[idx]);
        p += strlens(wordlist[idx]);
        *p = (i < mlen - 1) ? ' ' : 0;
        p++;
    }

    return mnemo;
}


int wallet_mnemonic_check(const char *mnemo)
{
    uint32_t i, j, k, ki, bi, n;
    int chksum = 0;
    char *sham[MAX_SEED_WORDS] = {NULL};
    char current_word[10];
    uint8_t bits[32 + 1];

    if (!mnemo) {
        //commander_fill_report("seed", FLAG_ERR_MNEMO_EMPTY, ERROR);
        return STATUS_ERROR;
    }

    // check number of words
    n = wallet_split_seed(sham, mnemo);
    memset(sham, 0, sizeof(sham));

    if (n != 12 && n != 18 && n != 24) {
        //commander_fill_report("seed", FLAG_ERR_MNEMO_NUM_WORDS, ERROR);
        return STATUS_ERROR;
    }

    memset(bits, 0, sizeof(bits));
    i = 0;
    bi = 0;
    while (mnemo[i]) {
        j = 0;
        while (mnemo[i] != ' ' && mnemo[i] != 0) {
            if (j >= sizeof(current_word)) {
                //commander_fill_report("seed", FLAG_ERR_MNEMO_WORD, ERROR);
                return STATUS_ERROR;
            }
            current_word[j] = mnemo[i];
            i++;
            j++;
        }
        current_word[j] = 0;
        if (mnemo[i] != 0) {
            i++;
        }
        k = 0;
        for (;;) {
            if (!wordlist[k]) { // word not found
                //commander_fill_report("seed", FLAG_ERR_MNEMO_WORD, ERROR);
                return STATUS_ERROR;
            }
            if (strcmp(current_word, wordlist[k]) == 0) { // word found on index k
                for (ki = 0; ki < 11; ki++) {
                    if (k & (1 << (10 - ki))) {
                        bits[bi / 8] |= 1 << (7 - (bi % 8));
                    }
                    bi++;
                }
                break;
            }
            k++;
        }
    }
    if (bi != n * 11) {
        //commander_fill_report("seed", FLAG_ERR_MNEMO_CHECK, ERROR);
        return STATUS_ERROR;
    }
    bits[32] = bits[n * 4 / 3];
    sha256_Raw(bits, n * 4 / 3, bits);
    if (n == 12) {
        chksum = (bits[0] & 0xF0) == (bits[32] & 0xF0); // compare first 4 bits
    } else if (n == 18) {
        chksum = (bits[0] & 0xFC) == (bits[32] & 0xFC); // compare first 6 bits
    } else if (n == 24) {
        chksum = bits[0] == bits[32]; // compare 8 bits
    }

    if (!chksum) {
        //commander_fill_report("seed", FLAG_ERR_MNEMO_CHECKSUM, ERROR);
        return STATUS_ERROR;
    }

    return STATUS_SUCCESS;
}


void wallet_mnemonic_to_seed(const char *mnemo, const char *passphrase,
                             uint8_t s[512 / 8],
                             void (*progress_callback)(uint32_t current, uint32_t total))
{
    static uint8_t salt[8 + SALT_LEN_MAX + 4];
    int saltlen = 0;
    memset(salt, 0, sizeof(salt));
    memcpy(salt, "mnemonic", 8);
    if (passphrase) {
        saltlen = strlens(passphrase);
        //memcpy(salt + 8, passphrase, saltlen);
        snprintf((char *)salt + 8, SALT_LEN_MAX, "%s", passphrase);
    }
    saltlen += 8;
    pbkdf2_hmac_sha512((const uint8_t *)mnemo, strlens(mnemo), salt, saltlen,
                       BIP39_PBKDF2_ROUNDS, s, 512 / 8, progress_callback);
}


// Returns 0 if inputs (i.e. prevOutHash's) and outputs are the same as previously used
int wallet_check_input_output(const char *hex, uint64_t hex_len, char *v_input,
                              char *v_output, int *input_cnt)
{
    uint64_t j, in_cnt, out_cnt, n_len, id_start, idx = 0;
    int len, not_same_input, not_same_output;
    char input[COMMANDER_REPORT_SIZE] = {0};

    idx += 8;                                       // skip version number

    // Inputs
    if (hex_len < idx + 16) {
        return STATUS_ERROR;
    }
    idx += utils_varint_to_uint64(hex + idx, &in_cnt);     // skip inCount
    for (j = 0; j < in_cnt; j++) {
        strncat(input, hex + idx, 64);              // copy prevOutHash
        idx += 64;                                  // skip prevOutHash
        idx += 8;                                   // skip preOutIndex
        if (hex_len < idx + 16) {
            return STATUS_ERROR;
        }
        idx += utils_varint_to_uint64(hex + idx, &n_len); // skip scriptSigLen
        idx += n_len * 2;                           // skip scriptSig (chars = 2 * bytes)
        idx += 8;                                   // skip sequence number
    }
    *input_cnt = in_cnt;

    // Outputs
    id_start = idx;
    if (hex_len < idx + 16) {
        return STATUS_ERROR;
    }
    idx += utils_varint_to_uint64(hex + idx, &out_cnt);     // skip outCount
    for (j = 0; j < out_cnt; j++) {
        idx += 16;                                  // skip outValue
        if (hex_len < idx + 16) {
            return STATUS_ERROR;
        }
        idx += utils_varint_to_uint64(hex + idx, &n_len); // skip outScriptLen
        idx += n_len * 2;                           // skip outScript (chars = 2 * bytes)
    }
    len = idx - id_start;

    not_same_input  = memcmp(v_input, input, COMMANDER_REPORT_SIZE);
    not_same_output = memcmp(v_output, hex + id_start,
                             len < COMMANDER_REPORT_SIZE ?
                             len : COMMANDER_REPORT_SIZE);

    // Return current inputs and outputs
    memcpy(v_input, input, COMMANDER_REPORT_SIZE);
    memset(v_output, 0, COMMANDER_REPORT_SIZE);
    memcpy(v_output, hex + id_start,
           len < COMMANDER_REPORT_SIZE ?
           len : COMMANDER_REPORT_SIZE);


    if (not_same_input || not_same_output) {
        return STATUS_VERIFY_DIFFERENT;
    } else {
        return STATUS_VERIFY_SAME;
    }
}


char *wallet_deserialize_output(const char *hex, uint64_t hex_len, const char *keypath,
                                int keypath_len)
{
    uint64_t j, cnt = 0, n_cnt, n_len, idx = 0, outValue;
    char outval[64], outaddr[256];
    static char output[COMMANDER_REPORT_SIZE] = {0};

    int change_addr_present = 0;
    char address[36];
    uint8_t pubkeyhash[20];
    uint8_t pub_key33[33];
    uint8_t *priv_key_master = memory_master(NULL);
    uint8_t *chain_code = memory_chaincode(NULL);
    HDNode node;


    if (!memcmp(priv_key_master, MEM_PAGE_ERASE, 32) ||
            !memcmp(chain_code, MEM_PAGE_ERASE, 32)) {
        return NULL;
    }

    memset(output, 0, COMMANDER_REPORT_SIZE);

    // Outputs
    if (hex_len < idx + 16) {
        return NULL;
    }
    idx += utils_varint_to_uint64(hex + idx, &n_cnt); // count
    strcat(output, "{\"verify_output\": [ ");
    for (j = 0; j < n_cnt; j++) {
        // outValue
        memset(outval, 0, sizeof(outval));
        strncpy(outval, hex + idx, 16);
        utils_reverse_hex(outval, 16);
        sscanf(outval, "%" PRIx64, &outValue);
        idx += 16;
        if (hex_len < idx + 16) {
            return NULL;
        }
        idx += utils_varint_to_uint64(hex + idx, &n_len);

        memset(outval, 0, sizeof(outval));
        memset(outaddr, 0, sizeof(outaddr));
        sprintf(outval, "{\"value\": %" PRIu64 ", ", outValue);
        sprintf(outaddr, "\"script\": \"%.*s\"}", (int)n_len * 2, hex + idx);
        idx += n_len * 2; // chars = 2 * bytes

        if (keypath && keypath_len > 0) {
            if (wallet_generate_key(&node, keypath, keypath_len, priv_key_master,
                                    chain_code) != STATUS_SUCCESS) {
                return NULL;
            }
            uECC_get_public_key33(node.private_key, pub_key33);
            wallet_get_pubkeyhash(pub_key33, pubkeyhash);
            wallet_get_address(pub_key33, 0, address, 36);
            if (strstr(outaddr, utils_uint8_to_hex(pubkeyhash, 20))) {
                change_addr_present++;
                continue;
            }
        }

        if (cnt > 0) {
            strcat(output, ", ");
        } else {
            cnt++;
        }
        strcat(output, outval);
        strcat(output, outaddr);
    }
    strcat(output, " ] }");
    memset(&node, 0, sizeof(HDNode));

    if (change_addr_present || n_cnt == 1) {
        return output;
    } else {
        // More than 1 output but a change address is not present.
        // Consider this an error in order to prevent MITM attacks.
        return NULL;
    }
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

