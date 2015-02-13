/*

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



#ifndef _WALLET_H_
#define _WALLET_H_

#include <stdint.h>

#define LENVARINT 20

/* BIP32 */
uint16_t *wallet_index_from_mnemonic(const char *mnemo, const char **wordlist);
char *wallet_mnemonic_from_index(const uint16_t *index);
void wallet_master_from_mnemonic(char *mnemo, int m_len, const char *salt, int s_len, int strength);
void wallet_sign(const char *message, int msg_len, char *keypath, int encoding);
void wallet_report_xpub(char *keypath);
/* Bitcoin formats */
int  wallet_sig_to_der(const uint8_t *sig, uint8_t *der);
void wallet_get_pubkeyhash(const uint8_t *pub_key, uint8_t *pubkeyhash);
void wallet_get_address_raw(const uint8_t *pub_key, uint8_t version, uint8_t *addr_raw);
void wallet_get_address(const uint8_t *pub_key, uint8_t version, char *addr, int addrsize);
void wallet_get_wif(const uint8_t *priv_key, uint8_t version, char *wif, int wifsize);


#endif
