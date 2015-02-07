#include <string.h>

#include "ripemd160.h"
#include "uECC.h"
#include "bip32.h"
#include "sha2.h"
#include "hmac.h"


int hdnode_from_seed(uint8_t *seed, int seed_len, HDNode *out)
{
	uint8_t I[32 + 32];
	memset(out, 0, sizeof(HDNode));
	out->depth = 0;
	out->fingerprint = 0x00000000;
    out->child_num = 0;
	hmac_sha512((uint8_t *)"Bitcoin seed", 12, seed, seed_len, I);
	memcpy(out->private_key, I, 32);
	
    if (!uECC_isValid(out->private_key)) {
		memset(I, 0, sizeof(I));
        return 0;
    }
    
    memcpy(out->chain_code, I + 32, 32);
	hdnode_fill_public_key(out);
    memset(I, 0, sizeof(I));
	return 1;
}


// write 4 big endian bytes
static void write_be(uint8_t *data, uint32_t x)
{
	data[0] = x >> 24;
	data[1] = x >> 16;
	data[2] = x >> 8;
	data[3] = x;
}


int hdnode_private_ckd(HDNode *inout, uint32_t i)
{
	uint8_t data[1 + 32 + 4];
	uint8_t I[32 + 32];
	uint8_t fingerprint[32];
    uint8_t p[32], z[32];

	if (i & 0x80000000) { // private derivation
		data[0] = 0;
		memcpy(data + 1, inout->private_key, 32);
	} else { // public derivation
		memcpy(data, inout->public_key, 33);
	}
	write_be(data + 33, i);
    
    sha256_Raw(inout->public_key, 33, fingerprint);
	ripemd160(fingerprint, 32, fingerprint);
	inout->fingerprint = (fingerprint[0] << 24) + (fingerprint[1] << 16) + (fingerprint[2] << 8) + fingerprint[3];

	memcpy(p, inout->private_key, 32);

	hmac_sha512(inout->chain_code, 32, data, sizeof(data), I);
	memcpy(inout->chain_code, I + 32, 32);
	memcpy(inout->private_key, I, 32);

	memcpy(z, inout->private_key, 32);

    if (!uECC_isValid(z)) {
	    memset(data, 0, sizeof(data));	
		memset(I, 0, sizeof(I));
        return 0;
    }


    uECC_generate_private_key(inout->private_key, p, z);
	
    if (!uECC_isValid(inout->private_key)) {
	    memset(data, 0, sizeof(data));	
		memset(I, 0, sizeof(I));
        return 0;
    }

	inout->depth++;
	inout->child_num = i;

	hdnode_fill_public_key(inout); // very slow

    memset(data, 0, sizeof(data));	
    memset(I, 0, sizeof(I));	
	return 1;
}


void hdnode_fill_public_key(HDNode *node)
{
	uECC_get_public_key33(node->private_key, node->public_key);
}

