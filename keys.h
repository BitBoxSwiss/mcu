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



#ifndef _KEYS_H_
#define _KEYS_H_

#include <stdint.h>

#define LENVARINT 20

uint16_t *index_from_mnemonic_bip32(const char *mnemonic);
char *mnemonic_from_index_bip32(const uint16_t *index);
void master_from_mnemonic_bip32(char *mnemo, int m_len, const char *salt, int s_len, int strength);
void sign_bip32(const char *message, char *keypath, int encoding);
void report_master_public_key_bip32(void);

uint16_t *index_from_mnemonic_electrum(const char *mnemonic);
char *mnemonic_from_seed_electrum(char *seed_hex);
void master_from_mnemonic_electrum(const char *mnemo, int m_len);
void sign_electrum(const char *message, char *keypath, int encoding);
void report_master_public_key_electrum(void); 

#endif
