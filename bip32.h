#ifndef _BIP32_H_
#define _BIP32_H_


#include <stdint.h>


typedef struct {
	uint32_t depth;
	uint32_t fingerprint;	
    uint32_t child_num;
	uint8_t chain_code[32];
	uint8_t private_key[32];
	uint8_t public_key[33];
} HDNode;


#define hdnode_private_ckd_prime(X, I) hdnode_private_ckd((X), ((I) | 0x80000000))


int hdnode_from_seed(uint8_t *seed, int seed_len, HDNode *out);
int hdnode_private_ckd(HDNode *inout, uint32_t i);
void hdnode_fill_public_key(HDNode *node);


#endif
