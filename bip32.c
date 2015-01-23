#include <string.h>

#include "ripemd160.h"
#include "bignum.h"
#include "ecdsa.h"
#include "bip32.h"
#include "sha2.h"
#include "hmac.h"


void hdnode_from_xpub(uint32_t depth, uint32_t fingerprint, uint32_t child_num, uint8_t *chain_code, uint8_t *public_key, HDNode *out)
{
	out->depth = depth;
	out->fingerprint = fingerprint;
	out->child_num = child_num;
	memcpy(out->chain_code, chain_code, 32);
	memset(out->private_key, 0, 32);
	memcpy(out->public_key, public_key, 33);
}


void hdnode_from_xprv(uint32_t depth, uint32_t fingerprint, uint32_t child_num, uint8_t *chain_code, uint8_t *private_key, HDNode *out)
{
	out->depth = depth;
	out->fingerprint = fingerprint;
	out->child_num = child_num;
	memcpy(out->chain_code, chain_code, 32);
	memcpy(out->private_key, private_key, 32);
	hdnode_fill_public_key(out);
}


int hdnode_from_seed(uint8_t *seed, int seed_len, HDNode *out)
{
	uint8_t I[32 + 32];
	memset(out, 0, sizeof(HDNode));
	out->depth = 0;
	out->fingerprint = 0x00000000;
    out->child_num = 0;
	hmac_sha512((uint8_t *)"Bitcoin seed", 12, seed, seed_len, I);
	memcpy(out->private_key, I, 32);
	bignum256 a;
	bn_read_be(out->private_key, &a);
	if (bn_is_zero(&a) || !bn_is_less(&a, &order256k1)) { // == 0 or >= order
		memset(I, 0, sizeof(I));
        return 0;
	}
	memcpy(out->chain_code, I + 32, 32);
	hdnode_fill_public_key(out);
    memset(I, 0, sizeof(I));
	return 1;
}


int hdnode_private_ckd(HDNode *inout, uint32_t i)
{
	uint8_t data[1 + 32 + 4];
	uint8_t I[32 + 32];
	uint8_t fingerprint[32];
    bignum256 a, b;

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

	bn_read_be(inout->private_key, &a);

	hmac_sha512(inout->chain_code, 32, data, sizeof(data), I);
	memcpy(inout->chain_code, I + 32, 32);
	memcpy(inout->private_key, I, 32);

	bn_read_be(inout->private_key, &b);

	if (!bn_is_less(&b, &order256k1)) { // >= order
	    memset(data, 0, sizeof(data));	
	    memset(I, 0, sizeof(I));	
        return 0;
	}

	bn_addmod(&a, &b, &order256k1);

	if (bn_is_zero(&a)) {
	    memset(data, 0, sizeof(data));	
	    memset(I, 0, sizeof(I));	
		return 0;
	}

	inout->depth++;
	inout->child_num = i;
	bn_write_be(&a, inout->private_key);

	hdnode_fill_public_key(inout);

    memset(data, 0, sizeof(data));	
    memset(I, 0, sizeof(I));	
	return 1;
}


int hdnode_public_ckd(HDNode *inout, uint32_t i)
{
	uint8_t data[1 + 32 + 4];
	uint8_t I[32 + 32];
	uint8_t fingerprint[32];
    curve_point a, b;
	bignum256 c;

	if (i & 0x80000000) { // private derivation
		return 0;
	} else { // public derivation
		memcpy(data, inout->public_key, 33);
	}
	write_be(data + 33, i);

    sha256_Raw(inout->public_key, 33, fingerprint);
	ripemd160(fingerprint, 32, fingerprint);
	inout->fingerprint = (fingerprint[0] << 24) + (fingerprint[1] << 16) + (fingerprint[2] << 8) + fingerprint[3];

	memset(inout->private_key, 0, 32);
	if (!ecdsa_read_pubkey(inout->public_key, &a)) {
		return 0;
	}

	hmac_sha512(inout->chain_code, 32, data, sizeof(data), I);
	memcpy(inout->chain_code, I + 32, 32);
	bn_read_be(I, &c);

	if (!bn_is_less(&c, &order256k1)) { // >= order
		return 0;
	}

	scalar_multiply(&c, &b); // b = c * G
	point_add(&a, &b);       // b = a + b

#if USE_PUBKEY_VALIDATE
	if (!ecdsa_validate_pubkey(&b)) {
		return 0;
	}
#endif	
    
    inout->public_key[0] = 0x02 | (b.y.val[0] & 0x01);
	bn_write_be(&b.x, inout->public_key + 1);

	inout->depth++;
	inout->child_num = i;

	return 1;
}


void hdnode_fill_public_key(HDNode *node)
{
	ecdsa_get_public_key33(node->private_key, node->public_key);
}
