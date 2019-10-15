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


#ifndef _WALLET_H_
#define _WALLET_H_


#include <stdint.h>
#include "bip32.h"


// BIP44 keypath whitelist for the xpub command
// m / purpose' / coin_type' / account' / change / address_index
#define BIP44_PURPOSE_HARDENED true
#define BIP44_PURPOSE_P2PKH 44 // BIP44 legacy
#define BIP44_PURPOSE_P2WPKH_P2SH 49 // BIP49 segwit nested in pay to script hash
#define BIP44_PURPOSE_P2WPKH 84 // BIP84 native segwit
#define BIP44_COIN_TYPE_HARDENED true
#define BIP44_COIN_TYPE_BTC 0
#define BIP44_COIN_TYPE_TESTNET 1
#define BIP44_COIN_TYPE_LTC 2
#define BIP44_ACCOUNT_HARDENED true
#define BIP44_ACCOUNT_MAX 9// 10 accounts (0:9)
#define BIP44_CHANGE_HARDENED false
#define BIP44_CHANGE_MAX 0// A client is not expected to request an xpub on a change path
#define BIP44_ADDRESS_HARDENED false
#define BIP44_ADDRESS_MAX 9999// 10k addresses (0:9999)
#define BIP44_KEYPATH_ADDRESS_DEPTH 5
#define BIP44_PRIME 0x80000000

#define MIN_WALLET_DEPTH 2
#define MAX_PARSE_KEYPATH_LEVEL 10// For memory assignment only, can be increased independently of BIP44_KEYPATH_ADDRESS_DEPTH if needed
#if (MAX_PARSE_KEYPATH_LEVEL < BIP44_KEYPATH_ADDRESS_DEPTH)
#error "Max keypath level cannot be less than BIP44 depth"
#endif


typedef enum BIP44_LEVELS {
    BIP44_LEVEL_PURPOSE,
    BIP44_LEVEL_COIN_TYPE,
    BIP44_LEVEL_ACCOUNT,
    BIP44_LEVEL_CHANGE,
    BIP44_LEVEL_ADDRESS,
} BIP44_LEVELS;


/* BIP32 */
void wallet_set_hidden(int hide);
int wallet_is_hidden(void);
int wallet_is_locked(void);
int wallet_is_paired(void);
uint8_t *wallet_get_master(void);
uint8_t *wallet_get_chaincode(void);
int wallet_split_seed(char **seed_words, const char *message);
int wallet_seeded(void);
int wallet_erased(void);
int wallet_create(const char *passphrase, const char *entropy_in);
int wallet_check_pubkey(const char *pubkey, const char *keypath);
int wallet_sign(const char *message, const char *keypath);
int wallet_report_xpub(const char *keypath, char *xpub);
void wallet_report_id(char *id);
int wallet_check_keypath_prefix(const uint32_t
                                keypath0[MAX_PARSE_KEYPATH_LEVEL],
                                const uint32_t keypath1[MAX_PARSE_KEYPATH_LEVEL],
                                const uint32_t depth);
int wallet_check_change_keypath(const uint32_t utxo[MAX_PARSE_KEYPATH_LEVEL],
                                const uint32_t change[MAX_PARSE_KEYPATH_LEVEL],
                                const uint32_t change_depth);
int wallet_parse_bip44_keypath(HDNode *node,
                               uint32_t keypath_array[BIP44_KEYPATH_ADDRESS_DEPTH],
                               uint32_t *depth, const char *keypath, const uint8_t *privkeymaster,
                               const uint8_t *chaincodemaster);
int wallet_generate_key(HDNode *node, const char *keypath, const uint8_t *privkeymaster,
                        const uint8_t *chaincodemaster);

/* BIP39 */
int wallet_generate_node(const char *passphrase, const char *entropy, HDNode *node);

/* Bitcoin formats */
void wallet_get_pubkeyhash(const uint8_t *pub_key, uint8_t *pubkeyhash);
void wallet_get_address_raw(const uint8_t *pub_key, uint8_t version, uint8_t *addr_raw);
void wallet_get_address(const uint8_t *pub_key, uint8_t version, char *addr,
                        int addrsize);
void wallet_get_wif(const uint8_t *priv_key, uint8_t version, char *wif, int wifsize);


#endif
