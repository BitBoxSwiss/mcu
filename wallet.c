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


#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "commander.h"
#include "ripemd160.h"
#include "wallet.h"
#include "memory.h"
#include "random.h"
#include "base64.h"
#include "base58.h"
#include "utils.h"
#include "bip32.h"
#include "bip39.h"
#include "sha2.h"
#include "uECC.h"
#include "led.h"


extern const uint8_t MEM_PAGE_ERASE[MEM_PAGE_LEN];
extern const uint16_t MEM_PAGE_ERASE_2X[MEM_PAGE_LEN];

static HDNode node;
static char mnemonic[256]; // longer than max wordlength+1  *  max numwords  +  1 
						   //		for bip32/39_english -> (8+1)*24+1 = 217
static uint16_t seed_index[25]; // longer than max numwords + 1
static uint8_t seed[64];
static uint8_t rand_data_32[32];


// Avoid leaving secrets in RAM
static void clear_static_variables(void)
{
    memset(&node, 0, sizeof(HDNode));
    memset(seed_index, 0, sizeof(seed_index));
    memset(seed, 0, sizeof(seed));
    memset(mnemonic, 0, sizeof(mnemonic));
    memset(rand_data_32, 0, sizeof(rand_data_32));
}


static int split_seed(char **seed_words, const char *message)
{
    int i = 0;
    char delim[] = " ,"; 
    static char msg[256];
    
    memset(msg, 0, 256);
    memcpy(msg, message, strlen(message));
    seed_words[i] = strtok(msg, delim);
    for (i = 0; seed_words[i] != NULL; seed_words[++i] = strtok(NULL, delim)) { }
    return i;
}


static void wallet_sign_generic_report(const uint8_t *priv_key, const char *message, int msg_len, int encoding)
{
    if (encoding == ATTR_der_) {
        int der_len;
        uint8_t sig[64]; 
        uint8_t der[64]; 
        if (!uECC_sign_double(priv_key, hex_to_uint8(message), msg_len / 2, sig)) {
            fill_report("sign", "Could not sign data.", ERROR);
        } else {
            der_len = wallet_sig_to_der(sig, der);
            fill_report("sign", uint8_to_hex(der, der_len), SUCCESS);
        } 
    } else if (encoding == ATTR_none_) {
        uint8_t sig[64]; 
        if (msg_len != (32 * 2)) {
            fill_report("sign", "Incorrect data length. "
                        "A 32-byte hexadecimal (64 characters) is expected.", ERROR);
        } else if (!uECC_sign_digest(priv_key, hex_to_uint8(message), sig)) {
            fill_report("sign", "Could not sign data.", ERROR);
        } else {
            fill_report("sign", uint8_to_hex(sig, 64), SUCCESS);
        }
    } else {
        fill_report("sign", "Invalid encoding method [1].", ERROR);
    }
}


uint16_t *wallet_index_from_mnemonic(const char *mnemo, const char **wordlist)
{
    int i, j, k, seed_words_n;
    char *seed_word[24] = {NULL}; 
    memset(seed_index, 0, sizeof(seed_index));
    seed_words_n = split_seed(seed_word, mnemo);
   
    k = 0;
    for (i = 0; i < seed_words_n; i++) {
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
	const char **wordlist = mnemonic_wordlist();
    
    memset(mnemonic, 0, sizeof(mnemonic));
    for (i = 0; idx[i]; i++) {
        strcat(mnemonic, wordlist[idx[i] - 1]);
        strcat(mnemonic, " ");
    }
    return mnemonic;
}


void wallet_master_from_mnemonic(char *mnemo, int m_len, const char *salt, int s_len, int strength)
{
    clear_static_variables();

    if (mnemo == NULL) {
        if (!strength) { strength = 256; }
	    if (strength % 32 || strength < 128 || strength > 256) {
            fill_report("seed", "Strength must be a multiple of 32 between 128 and 256.", ERROR); 
		    return;
	    }
        random_bytes(rand_data_32, 32, 1);
	    mnemo = mnemonic_from_data(rand_data_32, strength / 8);
		memcpy(mnemonic, mnemo, strlen(mnemo));
    } else {
		memcpy(mnemonic, mnemo, m_len);
	}

    if (mnemonic_check(mnemonic) == 0) {
        // error report is filled inside mnemonic_check()
        return;
    }

    if (salt == NULL) {
        mnemonic_to_seed(mnemonic, "", seed, 0); 
    } else { 
		char s[s_len];
		memcpy(s, salt, s_len);
        mnemonic_to_seed(mnemonic, s, seed, 0); 
    } 

	hdnode_from_seed(seed, sizeof(seed), &node);
    
    if (!memcmp(memory_master(node.private_key), MEM_PAGE_ERASE, 32)  ||
        !memcmp(memory_chaincode(node.chain_code), MEM_PAGE_ERASE, 32) ||
        !memcmp(memory_mnemonic(wallet_index_from_mnemonic(mnemonic, mnemonic_wordlist())), MEM_PAGE_ERASE_2X, 64)) {    
        fill_report("seed", "Problem saving BIP32 master key.", ERROR); 
    } else {
        fill_report("seed", "success", SUCCESS);
    }
    clear_static_variables();
}


static void wallet_generate_key(char *key_path, const uint8_t *privkeymaster, const uint8_t *chaincode)
{
    unsigned long idx;
    char *pch;
   
    node.depth = 0;
    node.child_num = 0;
	node.fingerprint = 0x00000000;
    memcpy(node.chain_code, chaincode, 32);
    memcpy(node.private_key, privkeymaster, 32);
	hdnode_fill_public_key(&node);
    
    pch = strtok(key_path, " /,m\\");
    while (pch != NULL) {
        sscanf(pch, "%lu", &idx); 
        if (pch[strlen(pch)-1] == '\'' ||
            pch[strlen(pch)-1] == 'p'  ||
            pch[strlen(pch)-1] == 'h'  ||
            pch[strlen(pch)-1] == 'H') {
            hdnode_private_ckd_prime(&node, idx); 
        } else {
            hdnode_private_ckd(&node, idx); 
        }
        pch = strtok(NULL, " /,m\\");
    } 
	//char xpriv[112];
    //hdnode_serialize_private(&node, xpriv, sizeof(xpriv));
    //printf("xpriv:    %s\n",xpriv); 
}


void wallet_report_xpub(char *keypath)
{
	char xpub[112];
    uint8_t *priv_key_master = memory_master(NULL);
    uint8_t *chain_code = memory_chaincode(NULL);
    
    if (!memcmp(priv_key_master, MEM_PAGE_ERASE, 32) || 
        !memcmp(chain_code, MEM_PAGE_ERASE, 32)) {
        fill_report("xpub", "A bip32 master private key is not set.", ERROR);
    } else {
        wallet_generate_key(keypath, priv_key_master, chain_code);
	    hdnode_serialize_public(&node, xpub, sizeof(xpub));
        fill_report("xpub", xpub, SUCCESS);
    }
    clear_static_variables();
}    


void wallet_sign(const char *message, int msg_len, char *keypath, int encoding)
{
    uint8_t *priv_key_master = memory_master(NULL);
    uint8_t *chain_code = memory_chaincode(NULL);
    
    if (!memcmp(priv_key_master, MEM_PAGE_ERASE, 32) ||
        !memcmp(chain_code, MEM_PAGE_ERASE, 32)) {    
        fill_report("sign", "A BIP32 master private key is not set.", ERROR); 
    } else {
        wallet_generate_key(keypath, priv_key_master, chain_code);
        wallet_sign_generic_report(node.private_key, message, msg_len, encoding);
    }
    clear_static_variables();
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

int wallet_sig_to_der(const uint8_t *sig, uint8_t *der)
{
	int i;
	uint8_t *p = der, *len, *len1, *len2;
	*p = 0x30; p++;                        // sequence
	*p = 0x00; len = p; p++;               // len(sequence)

	*p = 0x02; p++;                        // integer
	*p = 0x00; len1 = p; p++;              // len(integer)

	// process R
	i = 0;
	while (sig[i] == 0 && i < 32) { i++; } // skip leading zeroes
	if (sig[i] >= 0x80) { // put zero in output if MSB set
		*p = 0x00; p++; *len1 = *len1 + 1;
	}
	while (i < 32) { // copy bytes to output
		*p = sig[i]; p++; *len1 = *len1 + 1; i++;
	}

	*p = 0x02; p++;                        // integer
	*p = 0x00; len2 = p; p++;              // len(integer)

	// process S
	i = 32;
	while (sig[i] == 0 && i < 64) { i++; } // skip leading zeroes
	if (sig[i] >= 0x80) { // put zero in output if MSB set
		*p = 0x00; p++; *len2 = *len2 + 1;
	}
	while (i < 64) { // copy bytes to output
		*p = sig[i]; p++; *len2 = *len2 + 1; i++;
	}

	*len = *len1 + *len2 + 4;
	return *len + 2;
}
