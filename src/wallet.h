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


/* BIP32 */
int wallet_split_seed(char **seed_words, const char *message);
int wallet_master_from_xpriv(char *src);
int wallet_seeded(void);
int wallet_generate_master(void);
int wallet_check_pubkey(const char *pubkey, const char *keypath);
int wallet_sign(const char *message, const char *keypath);
void wallet_report_xpriv(const char *keypath, char *xpub);
void wallet_report_xpub(const char *keypath, char *xpub);
void wallet_report_id(char *id);
int wallet_generate_key(HDNode *node, const char *keypath, const uint8_t *privkeymaster,
                        const uint8_t *chaincode);
/* Bitcoin formats */
void wallet_get_pubkeyhash(const uint8_t *pub_key, uint8_t *pubkeyhash);
void wallet_get_address_raw(const uint8_t *pub_key, uint8_t version, uint8_t *addr_raw);
void wallet_get_address(const uint8_t *pub_key, uint8_t version, char *addr,
                        int addrsize);
void wallet_get_wif(const uint8_t *priv_key, uint8_t version, char *wif, int wifsize);


#endif
