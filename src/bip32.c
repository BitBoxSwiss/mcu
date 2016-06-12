/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 * Copyright (c) 2015-2016 Douglas J. Bakkum
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */


#include <string.h>

#include "ripemd160.h"
#include "base58.h"
#include "bip32.h"
#include "utils.h"
#include "flags.h"
#include "sha2.h"
#include "hmac.h"
#include "ecc.h"


// write 4 big endian bytes
static void write_be(uint8_t *data, uint32_t x)
{
    data[0] = x >> 24;
    data[1] = x >> 16;
    data[2] = x >> 8;
    data[3] = x;
}


// read 4 big endian bytes
static uint32_t read_be(const uint8_t *data)
{
    return (((uint32_t)data[0]) << 24) |
           (((uint32_t)data[1]) << 16) |
           (((uint32_t)data[2]) << 8)  |
           (((uint32_t)data[3]));
}


int hdnode_from_seed(const uint8_t *seed, int seed_len, HDNode *out)
{
    uint8_t I[32 + 32];
    memset(out, 0, sizeof(HDNode));
    out->depth = 0;
    out->fingerprint = 0x00000000;
    out->child_num = 0;
    hmac_sha512((const uint8_t *)"Bitcoin seed", 12, seed, seed_len, I);
    memcpy(out->private_key, I, 32);

    if (!ecc_isValid(out->private_key)) {
        utils_zero(I, sizeof(I));
        return DBB_ERROR;
    }

    memcpy(out->chain_code, I + 32, 32);
    hdnode_fill_public_key(out);
    utils_zero(I, sizeof(I));
    return DBB_OK;
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
    inout->fingerprint = (fingerprint[0] << 24) + (fingerprint[1] << 16) +
                         (fingerprint[2] << 8) + fingerprint[3];

    memcpy(p, inout->private_key, 32);

    hmac_sha512(inout->chain_code, 32, data, sizeof(data), I);
    memcpy(inout->chain_code, I + 32, 32);
    memcpy(inout->private_key, I, 32);

    memcpy(z, inout->private_key, 32);

    if (!ecc_isValid(z)) {
        utils_zero(data, sizeof(data));
        utils_zero(I, sizeof(I));
        return DBB_ERROR;
    }

    if (!ecc_generate_private_key(inout->private_key, p, z)) {
        utils_zero(data, sizeof(data));
        utils_zero(I, sizeof(I));
        return DBB_ERROR;
    }

    inout->depth++;
    inout->child_num = i;

    hdnode_fill_public_key(inout);

    utils_zero(data, sizeof(data));
    utils_zero(I, sizeof(I));
    return DBB_OK;
}


void hdnode_fill_public_key(HDNode *node)
{
    ecc_get_public_key33(node->private_key, node->public_key);
}


static void hdnode_serialize(const HDNode *node, uint32_t version, char use_public,
                             char *str, int strsize)
{
    uint8_t node_data[78];
    write_be(node_data, version);
    node_data[4] = node->depth;
    write_be(node_data + 5, node->fingerprint);
    write_be(node_data + 9, node->child_num);
    memcpy(node_data + 13, node->chain_code, 32);
    if (use_public) {
        memcpy(node_data + 45, node->public_key, 33);
    } else {
        node_data[45] = 0;
        memcpy(node_data + 46, node->private_key, 32);
    }
    base58_encode_check(node_data, 78, str, strsize);
}


void hdnode_serialize_public(const HDNode *node, char *str, int strsize)
{
    hdnode_serialize(node, 0x0488B21E, 1, str, strsize);
}


void hdnode_serialize_private(const HDNode *node, char *str, int strsize)
{
    hdnode_serialize(node, 0x0488ADE4, 0, str, strsize);
}


// check for validity of curve point in case of public data not performed
int hdnode_deserialize(const char *str, HDNode *node)
{
    uint8_t node_data[78];
    memset(node, 0, sizeof(HDNode));
    if (!base58_decode_check(str, node_data, sizeof(node_data))) {
        return DBB_ERROR;
    }
    uint32_t version = read_be(node_data);
    if (version == 0x0488B21E) { // public node
        memcpy(node->public_key, node_data + 45, 33);
    } else if (version == 0x0488ADE4) { // private node
        if (node_data[45]) { // invalid data
            return DBB_ERROR;
        }
        memcpy(node->private_key, node_data + 46, 32);
        hdnode_fill_public_key(node);
    } else {
        return DBB_ERROR; // invalid version
    }
    node->depth = node_data[4];
    node->fingerprint = read_be(node_data + 5);
    node->child_num = read_be(node_data + 9);
    memcpy(node->chain_code, node_data + 13, 32);
    return DBB_OK;
}
