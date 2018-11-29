/*

 The MIT License (MIT)

 Copyright (c) 2015-2018 Douglas J. Bakkum

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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "commander.h"
#include "ataes132.h"
#include "cipher.h"
#include "memory.h"
#include "random.h"
#include "utils.h"
#include "flags.h"
#include "flash.h"
#include "hmac.h"
#include "sha2.h"
#include "aes.h"
#include "drivers/config/mcu.h"


#if ((MEM_PAGE_LEN != SHA256_DIGEST_LENGTH) || (MEM_PAGE_LEN * 2 != SHA512_DIGEST_LENGTH))
#error "Incompatible macro values"
#endif


// 16 consecutive user zones: 0x0000 to 0x0FFF
// Each zone contains 0x0100 bytes; read/write cannot cross zone boundaries
#define MEM_ERASED_ADDR                 0x0000// (uint8_t)  Zone 0 reserved for flags
#define MEM_SETUP_ADDR                  0x0002// (uint8_t)
#define MEM_ACCESS_ERR_ADDR             0x0004// (uint16_t)
#define MEM_PIN_ERR_ADDR                0x0006// (uint16_t)
#define MEM_UNLOCKED_ADDR               0x0008// (uint8_t)
#define MEM_EXT_FLAGS_ADDR              0x000A// (uint32_t) 32 possible extension flags
#define MEM_U2F_COUNT_ADDR              0x0010// (uint32_t)
#define MEM_MEMORY_MAP_VERSION_ADDR     0x0014// (uint32_t)
#if (FLASH_USERSIG_FLAG_LEN < (MEM_MEMORY_MAP_VERSION_ADDR + 4) || FLASH_USERSIG_FLAG_LEN >= 0x0100)
#error "Incorrect macro value for memory map"
#endif
#define MEM_MAP_ADDRS                   /*V0*/  /*V1*/  /* Memory map version */\
X(MEM_NAME_ADDR_IDX,                    0x0100, 0x0180)\
X(MEM_MASTER_BIP32_ADDR_IDX,            0x0200, 0x0280)\
X(MEM_MASTER_BIP32_CHAIN_ADDR_IDX,      0x0300, 0x0380)\
X(MEM_AESKEY_STAND_ADDR_IDX,            0x0400, 0x0480)\
X(MEM_AESKEY_SHARED_SECRET_ADDR_IDX,    0x0500, 0x0580)\
X(MEM_AESKEY_HIDDEN_ADDR_IDX,           0x0800, 0x0880)\
X(MEM_MASTER_ENTROPY_ADDR_IDX,          0x0900, 0x0980)\
X(MEM_MASTER_U2F_ADDR_IDX,              0x0A00, 0x0A80)\
X(MEM_HIDDEN_BIP32_ADDR_IDX,            0x0B00, 0x0C80)\
X(MEM_HIDDEN_BIP32_CHAIN_ADDR_IDX,      0x0B80, 0x0D80)
#define X(a, b, c) a,
enum MEM_MAPPING_ENUM { MEM_MAP_ADDRS };
#undef X
#define X(a, b, c) b,
uint16_t MEM_ADDR_V0[] = { MEM_MAP_ADDRS };
#undef X
#define X(a, b, c) c,
uint16_t MEM_ADDR_V1[] = { MEM_MAP_ADDRS };
#undef X
// Number of calls to memory_eeprom to store encrypted data.
//     Each call can read and/or write up to 32 bytes at a time.
//     For MEM_MAP_V0, 4 calls required. For MEM_MAP_V1, 3 calls
//     required but still use 4 calls in order to keep the code
//     cleaner, pad with 0xFFs:
//     [16-byte IV | 32-byte cipher | 16-byte AES pad | 32-byte hmac | 32-bytes 0xFF]
#define MEM_NUM_CRYPT_EEPROM_WRITES     4
// Version settings
#define MEM_MAP_V0                      MEM_DEFAULT_memory_map_version
#define MEM_MAP_V1                      0x00000001
#define ACTIVE_memory_map_version       MEM_MAP_V1


static uint8_t MEM_unlocked = MEM_DEFAULT_unlocked;
static uint8_t MEM_erased = MEM_DEFAULT_erased;
static uint8_t MEM_setup = MEM_DEFAULT_setup;
static uint32_t MEM_ext_flags = MEM_DEFAULT_ext_flags;
static uint32_t MEM_u2f_count = MEM_DEFAULT_u2f_count;
static uint16_t MEM_pin_err = DBB_ACCESS_INITIALIZE;
static uint16_t MEM_access_err = DBB_ACCESS_INITIALIZE;
static uint32_t MEM_memory_map_version = MEM_DEFAULT_memory_map_version;

__extension__ static uint8_t MEM_active_key[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_user_entropy[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_stand[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_hidden[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_verify[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_master_hww_entropy[] = {[0 ... MEM_PAGE_LEN - 1] = 0x00};
__extension__ static uint8_t MEM_master_hww_chain[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_master_hww[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_hidden_hww_chain[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_hidden_hww[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_master_u2f[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_name[] = {[0 ... MEM_PAGE_LEN - 1] = '0'};

__extension__ const uint8_t MEM_PAGE_ERASE[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ const uint16_t MEM_PAGE_ERASE_2X[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFFFF};
__extension__ const uint8_t MEM_PAGE_ERASE_FE[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFE};


static void memory_eeprom(const uint8_t *write_b, uint8_t *read_b, int32_t addr,
                          uint16_t len)
{
    // read current memory
    if (ataes_eeprom(len, addr, read_b, NULL) != DBB_OK) {
        HardFault_Handler();
    } else if (write_b) {
        // skip writing if memory does not change
        if (read_b) {
            if (MEMEQ(read_b, write_b, len)) {
                return; // success
            }
        }
        if (ataes_eeprom(len, addr, read_b, write_b) != DBB_OK) {
            HardFault_Handler();
        } else if (read_b) {
            if (MEMEQ(write_b, read_b, len)) {
                return; // success
            } else {
                // error
                if (len > 2) {
                    memcpy(read_b, MEM_PAGE_ERASE, len);
                }
                HardFault_Handler();
            }
        }
    }
    return;
}


// Encrypted storage
// `write_b` and `read_b` must be length `MEM_PAGE_LEN`
static uint8_t memory_eeprom_crypt(const uint8_t *write_b, uint8_t *read_b,
                                   uint8_t map_addr, uint32_t map_version)
{
    int enc_len, dec_len, i;
    char *enc, *dec, enc_r[MEM_PAGE_LEN * MEM_NUM_CRYPT_EEPROM_WRITES + 1] = {0};
    static uint8_t mempass[MEM_PAGE_LEN];
    int32_t addr;

    // Encrypt data saved to memory using an AES key obfuscated by the
    // bootloader bytes.
    memset(mempass, 0, sizeof(mempass));
    uint8_t usersig[FLASH_USERSIG_SIZE];
#ifndef TESTING
    sha256_Raw((uint8_t *)(FLASH_BOOT_START), FLASH_BOOT_LEN, mempass);
#endif
    flash_wrapper_read_usersig((uint32_t *)usersig, FLASH_USERSIG_SIZE / sizeof(uint32_t));
    if (!MEMEQ(usersig + FLASH_USERSIG_RN_START, MEM_PAGE_ERASE, FLASH_USERSIG_RN_LEN)) {
        hmac_sha256(mempass, MEM_PAGE_LEN, usersig + FLASH_USERSIG_RN_START, FLASH_USERSIG_RN_LEN,
                    mempass);
    }
    sha256_Raw(mempass, MEM_PAGE_LEN, mempass);
    switch (map_version) {
        case MEM_MAP_V0:
            addr = MEM_ADDR_V0[map_addr];
            sha256_Raw((const uint8_t *)(utils_uint8_to_hex(mempass, MEM_PAGE_LEN)), MEM_PAGE_LEN * 2,
                       mempass);
            sha256_Raw(mempass, MEM_PAGE_LEN, mempass);
            utils_clear_buffers(); // clean up mempass hex
            break;
        case MEM_MAP_V1:
            addr = MEM_ADDR_V1[map_addr];
            break;
        default:
            goto err;
    }

    if (write_b) {
        char enc_w[MEM_PAGE_LEN * MEM_NUM_CRYPT_EEPROM_WRITES + 1];
        memset(enc_w, 0xFF, sizeof(enc_w));
        enc_w[MEM_PAGE_LEN * MEM_NUM_CRYPT_EEPROM_WRITES] = '\0';
        switch (map_version) {
            case MEM_MAP_V0:
                enc = cipher_aes_b64_encrypt((unsigned char *)utils_uint8_to_hex(write_b, MEM_PAGE_LEN),
                                             MEM_PAGE_LEN * 2, &enc_len, mempass);
                utils_clear_buffers(); // clean up hex write_b
                if (!enc) {
                    goto err;
                }
                snprintf(enc_w, sizeof(enc_w), "%.*s", enc_len, enc);
                utils_zero(enc, enc_len);
                free(enc);
                break;
            case MEM_MAP_V1:
                enc = (char *)cipher_aes_hmac_encrypt((const unsigned char *)write_b, MEM_PAGE_LEN,
                                                      &enc_len, mempass);
                if (!enc) {
                    goto err;
                }
                if (sizeof(enc_w) < (size_t)enc_len) {
                    utils_zero(enc, enc_len);
                    free(enc);
                    goto err;
                }
                memcpy(enc_w, enc, enc_len);
                utils_zero(enc, enc_len);
                free(enc);
                break;
            default:
                goto err;
        }
        for (i = 0; i < MEM_NUM_CRYPT_EEPROM_WRITES; i++) {
            memory_eeprom((uint8_t *)enc_w + MEM_PAGE_LEN * i,
                          (uint8_t *)enc_r + MEM_PAGE_LEN * i, addr + MEM_PAGE_LEN * i,
                          MEM_PAGE_LEN);
        }
    } else if (read_b) {
        for (i = 0; i < MEM_NUM_CRYPT_EEPROM_WRITES; i++) {
            memory_eeprom(NULL, (uint8_t *)enc_r + MEM_PAGE_LEN * i, addr + MEM_PAGE_LEN * i,
                          MEM_PAGE_LEN);
        }
    } else {
        goto err;
    }

    switch (map_version) {
        case MEM_MAP_V0:
            dec = cipher_aes_b64_decrypt((unsigned char *)enc_r,
                                         MEM_PAGE_LEN * MEM_NUM_CRYPT_EEPROM_WRITES,
                                         &dec_len, mempass);
            if (!dec) {
                goto err;
            }
            memcpy(dec, utils_hex_to_uint8(dec), MEM_PAGE_LEN);
            utils_clear_buffers(); // clean up dec in utils_buffer
            break;
        case MEM_MAP_V1:
            // Encrypted length is length of cipher + IV + padding + hmac
            enc_len = MEM_PAGE_LEN + N_BLOCK + (N_BLOCK - (MEM_PAGE_LEN % N_BLOCK)) +
                      SHA256_DIGEST_LENGTH;
            dec = cipher_aes_hmac_decrypt((unsigned char *)enc_r, enc_len, &dec_len, mempass);
            if (!dec) {
                goto err;
            }
            break;
        default:
            goto err;
    }

    if (read_b) {
        memcpy(read_b, dec, MEM_PAGE_LEN);
    }

    utils_zero(dec, dec_len);
    free(dec);
    utils_zero(mempass, MEM_PAGE_LEN);
    return DBB_OK;
err:
    if (read_b) {
        // Randomize return value on error
        hmac_sha256(mempass, MEM_PAGE_LEN, read_b, MEM_PAGE_LEN, read_b);
    }
    utils_zero(mempass, MEM_PAGE_LEN);
    return DBB_ERROR;
}


static void memory_byte_flag(uint8_t *write_b, uint8_t *read_b,
                             int32_t addr, uint8_t byte_len)
{
    memory_eeprom(write_b, read_b, addr, byte_len);
    if (MEM_memory_map_version != MEM_DEFAULT_memory_map_version) {
        uint8_t usersig[FLASH_USERSIG_SIZE];
        if (flash_wrapper_read_usersig((uint32_t *)usersig,
                                       FLASH_USERSIG_SIZE / sizeof(uint32_t))) {
            utils_zero(usersig, sizeof(usersig));
            goto err;
        }
        if (write_b) {
            if (!MEMEQ(usersig + FLASH_USERSIG_FLAG_START + addr, write_b, byte_len)) {
                memcpy(usersig + FLASH_USERSIG_FLAG_START + addr, write_b, byte_len);
                flash_wrapper_erase_usersig();
                flash_wrapper_write_usersig((uint32_t *)usersig, FLASH_USERSIG_SIZE / sizeof(uint32_t));
            }
        }
        if (!MEMEQ(usersig + FLASH_USERSIG_FLAG_START + addr, read_b, byte_len)) {
            utils_zero(usersig, sizeof(usersig));
            goto err;
        }
        utils_zero(usersig, sizeof(usersig));
    }
    return;
err:
    memory_reset_hww();
}


static void memory_write_setup(uint8_t setup)
{
    memory_byte_flag(&setup, &MEM_setup, MEM_SETUP_ADDR, sizeof(MEM_setup));
}


static uint8_t memory_read_setup(void)
{
    memory_byte_flag(NULL, &MEM_setup, MEM_SETUP_ADDR, sizeof(MEM_setup));
    return MEM_setup;
}


void memory_write_memory_map_version(uint32_t v)
{
    memory_byte_flag((uint8_t *)&v, (uint8_t *)&MEM_memory_map_version,
                     MEM_MEMORY_MAP_VERSION_ADDR, sizeof(MEM_memory_map_version));
}


static uint32_t memory_read_memory_map_version(void)
{
    memory_byte_flag(NULL, (uint8_t *)&MEM_memory_map_version, MEM_MEMORY_MAP_VERSION_ADDR,
                     sizeof(MEM_memory_map_version));
    return MEM_memory_map_version;
}


static void memory_scramble_default_aeskeys(void)
{
    uint8_t number[32] = {0};
    random_bytes(number, sizeof(number), 0);
    memcpy(MEM_aeskey_stand, number, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_hidden, number, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_verify, number, MEM_PAGE_LEN);
    memcpy(MEM_active_key, number, MEM_PAGE_LEN);
}


static void memory_scramble_rn(void)
{
    uint32_t i = 0;
    uint8_t usersig[FLASH_USERSIG_SIZE];
    uint8_t number[FLASH_USERSIG_RN_LEN] = {0};
    random_bytes(number, FLASH_USERSIG_RN_LEN, 0);
    flash_wrapper_read_usersig((uint32_t *)usersig, FLASH_USERSIG_SIZE / sizeof(uint32_t));
    for (i = 0; i < FLASH_USERSIG_RN_LEN; i++) {
        usersig[i + FLASH_USERSIG_RN_START] ^= number[i];
    }
    flash_wrapper_erase_usersig();
    flash_wrapper_write_usersig((uint32_t *)usersig, FLASH_USERSIG_SIZE / sizeof(uint32_t));
}


void memory_setup(void)
{
    if (memory_read_setup()) {
        // One-time setup on factory install
        // Lock Config Memory:              OP       MODE  PARAMETER1  PARAMETER2
        const uint8_t ataes_cmd[] = {ATAES_CMD_LOCK, 0x02, 0x00, 0x00, 0x00, 0x00};
        // Return packet [Count(1) || Return Code (1) || CRC (2)]
        uint8_t ataes_ret[4] = {0};
        uint8_t ret = ataes_process(ataes_cmd, sizeof(ataes_cmd), ataes_ret, sizeof(ataes_ret));
        if (ret != DBB_OK || !ataes_ret[0] || ataes_ret[1]) {
            HardFault_Handler();
        }
        uint32_t c = 0x00000000;
        memory_write_memory_map_version(ACTIVE_memory_map_version);
        memory_reset_hww();
        memory_reset_u2f();
        memory_u2f_count_set(c);
        memory_write_setup(0x00);
    } else {
        memory_update_memory_map();
        memory_read_ext_flags();
        memory_read_erased();
        memory_master_u2f(NULL);// Load cache so that U2F speed is fast enough
        memory_read_access_err_count();// Load cache
        memory_u2f_count_read();
    }
    memory_scramble_default_aeskeys();
}


void memory_update_memory_map(void)
{
    // Future mappings can be updated sequentially through memory map versions.
    // This is useful, for example, if a firmware upgrade that updated a mapping was skipped.
    switch (memory_read_memory_map_version()) {
        case MEM_DEFAULT_memory_map_version: {
            // Remap ECC and AES key memory
            {
                uint8_t a, i, mem0[MEM_PAGE_LEN], mem1[MEM_PAGE_LEN], ret0, ret1;
                uint16_t addr_idx;
                uint16_t addr_idxs[] = {
                    MEM_MASTER_ENTROPY_ADDR_IDX,
                    MEM_MASTER_BIP32_ADDR_IDX,
                    MEM_MASTER_BIP32_CHAIN_ADDR_IDX,
                    MEM_HIDDEN_BIP32_ADDR_IDX,
                    MEM_HIDDEN_BIP32_CHAIN_ADDR_IDX,
                    MEM_AESKEY_STAND_ADDR_IDX,
                    MEM_AESKEY_SHARED_SECRET_ADDR_IDX,
                    MEM_AESKEY_HIDDEN_ADDR_IDX,
                    MEM_MASTER_U2F_ADDR_IDX,
                };
                memset(mem0, 0xFF, sizeof(mem0));
                memset(mem1, 0xFF, sizeof(mem1));
                for (a = 0; a < sizeof(addr_idxs) / sizeof(uint16_t); a++) {
                    addr_idx = addr_idxs[a];
                    while (1) {
                        ret0 = memory_eeprom_crypt(NULL, mem0, addr_idx, MEM_MAP_V0);
                        ret1 = memory_eeprom_crypt(NULL, mem1, addr_idx, MEM_MAP_V1);
                        if (ret0 == DBB_OK && ret1 != DBB_OK) {
                            // Copy memory; `continue` to verify the value was copied correctly
                            memory_eeprom_crypt(mem0, mem1, addr_idx, MEM_MAP_V1);
                            continue;
                        }
                        if (ret0 == DBB_OK && ret1 == DBB_OK) {
                            if (MEMEQ(mem0, mem1, MEM_PAGE_LEN)) {
                                // Set the old memory location to chip default 0xFF
                                for (i = 0; i < MEM_NUM_CRYPT_EEPROM_WRITES; i++) {
                                    memory_eeprom(MEM_PAGE_ERASE, NULL, MEM_ADDR_V0[addr_idx] + MEM_PAGE_LEN * i,
                                                  MEM_PAGE_LEN);
                                }
                            } else {
                                // Unexpected outcome; erase old memory location; set new memory location to chip default 0xFF
                                memory_eeprom_crypt(MEM_PAGE_ERASE, mem0, addr_idx, MEM_MAP_V0);
                                for (i = 0; i < MEM_NUM_CRYPT_EEPROM_WRITES; i++) {
                                    memory_eeprom(MEM_PAGE_ERASE, NULL, MEM_ADDR_V1[addr_idx] + MEM_PAGE_LEN * i,
                                                  MEM_PAGE_LEN);
                                }
                            }
                            continue;
                        }
                        if (ret0 != DBB_OK && ret1 == DBB_OK) {
                            // Remap completed
                            break;
                        }
                        if (ret0 != DBB_OK && ret1 != DBB_OK) {
                            // Unexpected condition; erase old memory location
                            memory_eeprom_crypt(MEM_PAGE_ERASE, mem0, addr_idx, MEM_MAP_V0);
                            continue;
                        }
                    }
                }
            }
            // Remap device name
            {
                uint8_t name[MEM_PAGE_LEN];
                memory_eeprom(NULL, name, MEM_ADDR_V0[MEM_NAME_ADDR_IDX], MEM_PAGE_LEN);
                memory_eeprom_crypt(name, NULL, MEM_NAME_ADDR_IDX, MEM_MAP_V1);
                memory_eeprom(MEM_PAGE_ERASE, NULL, MEM_ADDR_V0[MEM_NAME_ADDR_IDX], MEM_PAGE_LEN);
            }
            // Copy settings flags to FLASH
            {
                uint8_t usersig[FLASH_USERSIG_SIZE];
                uint8_t flags[FLASH_USERSIG_FLAG_LEN];
                memory_eeprom(NULL, flags, 0, sizeof(flags));
                flash_wrapper_read_usersig((uint32_t *)usersig, FLASH_USERSIG_SIZE / sizeof(uint32_t));
                memcpy(usersig + FLASH_USERSIG_FLAG_START, flags, sizeof(flags));
                flash_wrapper_erase_usersig();
                flash_wrapper_write_usersig((uint32_t *)usersig, FLASH_USERSIG_SIZE / sizeof(uint32_t));
            }
            // Update map version
            memory_write_memory_map_version(MEM_MAP_V1);
            /* FALLTHROUGH */
        }
        case ACTIVE_memory_map_version:
            break;
        default:
            commander_force_reset();
    }
}


void memory_erase_hww_seed(void)
{
    memory_master_hww_entropy(MEM_PAGE_ERASE);
    memory_master_hww_chaincode(MEM_PAGE_ERASE);
    memory_master_hww(MEM_PAGE_ERASE);
    memory_hidden_hww_chaincode(MEM_PAGE_ERASE_FE);
    memory_hidden_hww(MEM_PAGE_ERASE_FE);
    memory_random_password(PASSWORD_HIDDEN);
}

void memory_reset_hww(void)
{
    uint8_t u2f[MEM_PAGE_LEN];
    memcpy(u2f, MEM_master_u2f, MEM_PAGE_LEN);
    memory_scramble_rn();
    memory_master_u2f(u2f);
    memory_random_password(PASSWORD_STAND);
    memory_random_password(TFA_SHARED_SECRET);
    memory_random_password(PASSWORD_HIDDEN);
    memory_erase_hww_seed();
    memory_name(DEVICE_DEFAULT_NAME);
    memory_write_erased(MEM_DEFAULT_erased);
    memory_write_unlocked(MEM_DEFAULT_unlocked);
    memory_write_ext_flags(MEM_DEFAULT_ext_flags);
    memory_access_err_count(DBB_ACCESS_INITIALIZE);
    memory_pin_err_count(DBB_ACCESS_INITIALIZE);
    utils_zero(u2f, sizeof(u2f));
}


void memory_reset_u2f(void)
{
    // Create random master U2F key. It is independent of the HWW.
    // U2F is functional on fresh device without a seeded wallet.
    uint8_t number[32] = {0};
    random_bytes(number, sizeof(number), 0);
    memory_master_u2f(number);
    utils_zero(number, sizeof(number));
}


void memory_random_password(PASSWORD_ID id)
{
    uint8_t number[16] = {0};
    random_bytes(number, sizeof(number), 0);
    memory_write_aeskey(utils_uint8_to_hex(number, sizeof(number)), sizeof(number) * 2, id);
    utils_zero(number, sizeof(number));
    utils_clear_buffers();
}


void memory_clear(void)
{
    // Zero important variables in RAM on embedded MCU.
    memcpy(MEM_hidden_hww_chain, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_hidden_hww, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master_hww_chain, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master_hww, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master_hww_entropy, MEM_PAGE_ERASE, MEM_PAGE_LEN);
}


uint8_t *memory_name(const char *name)
{
    char name_capped_len[MEM_PAGE_LEN];
    if (strlens(name)) {
        memset(name_capped_len, 0, sizeof(name_capped_len));
        snprintf(name_capped_len, MEM_PAGE_LEN, "%s", name);
        memory_eeprom_crypt((const uint8_t *)name_capped_len, MEM_name, MEM_NAME_ADDR_IDX,
                            MEM_memory_map_version);
    } else {
        memory_eeprom_crypt(NULL, MEM_name, MEM_NAME_ADDR_IDX, MEM_memory_map_version);
    }
    return MEM_name;
}


uint8_t *memory_hidden_hww(const uint8_t *master)
{
    memory_eeprom_crypt(NULL, MEM_hidden_hww, MEM_HIDDEN_BIP32_ADDR_IDX,
                        MEM_memory_map_version);

    uint32_t ext_flags = memory_report_ext_flags();
    uint8_t legacy = !(ext_flags & MEM_EXT_MASK_NEW_HIDDEN_WALLET);
    if ((master == NULL) && (legacy || MEMEQ(MEM_hidden_hww, MEM_PAGE_ERASE, 32))) {
        // Backward compatible with firmware <=2.2.3
        return memory_master_hww_chaincode(NULL);
    }
    memory_eeprom_crypt(master, MEM_hidden_hww, MEM_HIDDEN_BIP32_ADDR_IDX,
                        MEM_memory_map_version);
    return MEM_hidden_hww;
}


uint8_t *memory_hidden_hww_chaincode(const uint8_t *chain)
{
    memory_eeprom_crypt(NULL, MEM_hidden_hww_chain, MEM_HIDDEN_BIP32_CHAIN_ADDR_IDX,
                        MEM_memory_map_version);
    uint32_t ext_flags = memory_report_ext_flags();
    uint8_t legacy = !(ext_flags & MEM_EXT_MASK_NEW_HIDDEN_WALLET);
    if ((chain == NULL) && (legacy || MEMEQ(MEM_hidden_hww_chain, MEM_PAGE_ERASE, 32))) {
        // Backward compatible with firmware <=2.2.3
        return memory_master_hww(NULL);
    }
    memory_eeprom_crypt(chain, MEM_hidden_hww_chain, MEM_HIDDEN_BIP32_CHAIN_ADDR_IDX,
                        MEM_memory_map_version);
    return MEM_hidden_hww_chain;
}


uint8_t *memory_master_hww(const uint8_t *master)
{
    memory_eeprom_crypt(master, MEM_master_hww, MEM_MASTER_BIP32_ADDR_IDX,
                        MEM_memory_map_version);
    return MEM_master_hww;
}


uint8_t *memory_master_hww_chaincode(const uint8_t *chain)
{
    memory_eeprom_crypt(chain, MEM_master_hww_chain, MEM_MASTER_BIP32_CHAIN_ADDR_IDX,
                        MEM_memory_map_version);
    return MEM_master_hww_chain;
}


uint8_t *memory_master_hww_entropy(const uint8_t *master_entropy)
{
    memory_eeprom_crypt(master_entropy, MEM_master_hww_entropy, MEM_MASTER_ENTROPY_ADDR_IDX,
                        MEM_memory_map_version);
    return MEM_master_hww_entropy;
}


uint8_t *memory_master_u2f(const uint8_t *master_u2f)
{
    memory_eeprom_crypt(master_u2f, MEM_master_u2f, MEM_MASTER_U2F_ADDR_IDX,
                        MEM_memory_map_version);
    return MEM_master_u2f;
}


uint8_t *memory_report_master_u2f(void)
{
    return MEM_master_u2f;
}


void memory_active_key_set(uint8_t *key)
{
    if (key) {
        memcpy(MEM_active_key, key, MEM_PAGE_LEN);
    }
}


uint8_t *memory_active_key_get(void)
{
    return MEM_active_key;
}

uint8_t memory_write_tfa_shared_secret(const uint8_t *secret)
{
    int ret = memory_eeprom_crypt(secret, MEM_aeskey_verify,
                                  MEM_AESKEY_SHARED_SECRET_ADDR_IDX, MEM_memory_map_version) - DBB_OK;
    if (ret) {
        return DBB_ERR_MEM_ATAES;
    } else {
        return DBB_OK;
    }
}

uint8_t memory_write_aeskey(const char *password, int len, PASSWORD_ID id)
{
    int ret = 0;
    uint8_t password_b[MEM_PAGE_LEN];
    memset(password_b, 0, MEM_PAGE_LEN);

    if (len < PASSWORD_LEN_MIN || strlens(password) < PASSWORD_LEN_MIN) {
        return DBB_ERR_IO_PASSWORD_LEN;
    }

    sha256_Raw((const uint8_t *)password, len, password_b);
    sha256_Raw(password_b, MEM_PAGE_LEN, password_b);

    switch ((int)id) {
        case PASSWORD_STAND:
            memcpy(MEM_aeskey_stand, password_b, MEM_PAGE_LEN);
            break;
        case PASSWORD_HIDDEN:
            memcpy(MEM_aeskey_hidden, password_b, MEM_PAGE_LEN);
            break;
        default: {
            /* never reached */
        }
    }

    ret |= memory_eeprom_crypt(MEM_aeskey_stand, MEM_aeskey_stand,
                               MEM_AESKEY_STAND_ADDR_IDX, MEM_memory_map_version) - DBB_OK;
    ret |= memory_eeprom_crypt(MEM_aeskey_hidden, MEM_aeskey_hidden,
                               MEM_AESKEY_HIDDEN_ADDR_IDX, MEM_memory_map_version) - DBB_OK;
    ret |= memory_eeprom_crypt(MEM_aeskey_verify, MEM_aeskey_verify,
                               MEM_AESKEY_SHARED_SECRET_ADDR_IDX, MEM_memory_map_version) - DBB_OK;

    utils_zero(password_b, MEM_PAGE_LEN);

    if (ret) {
        return DBB_ERR_MEM_ATAES;
    } else {
        return DBB_OK;
    }
}


void memory_read_aeskeys(void)
{
    static uint8_t read = 0;
    if (!read) {
        memory_eeprom_crypt(NULL, MEM_aeskey_stand, MEM_AESKEY_STAND_ADDR_IDX,
                            MEM_memory_map_version);
        memory_eeprom_crypt(NULL, MEM_aeskey_hidden, MEM_AESKEY_HIDDEN_ADDR_IDX,
                            MEM_memory_map_version);
        memory_eeprom_crypt(NULL, MEM_aeskey_verify, MEM_AESKEY_SHARED_SECRET_ADDR_IDX,
                            MEM_memory_map_version);
        sha256_Raw(MEM_aeskey_stand, MEM_PAGE_LEN, MEM_user_entropy);
        read++;
    }
}


uint8_t *memory_report_aeskey(PASSWORD_ID id)
{
    switch ((int)id) {
        case PASSWORD_STAND:
            return MEM_aeskey_stand;
        case PASSWORD_HIDDEN:
            return MEM_aeskey_hidden;
        case TFA_SHARED_SECRET:
            return MEM_aeskey_verify;
        default:
            return NULL;
    }
}


uint8_t *memory_report_user_entropy(void)
{
    return MEM_user_entropy;
}


uint8_t memory_report_setup(void)
{
    return MEM_setup;
}


void memory_write_unlocked(uint8_t u)
{
    memory_byte_flag(&u, &MEM_unlocked, MEM_UNLOCKED_ADDR, sizeof(MEM_unlocked));
}
uint8_t memory_read_unlocked(void)
{
    memory_byte_flag(NULL, &MEM_unlocked, MEM_UNLOCKED_ADDR, sizeof(MEM_unlocked));
    return MEM_unlocked;
}


void memory_write_erased(uint8_t erased)
{
    memory_byte_flag(&erased, &MEM_erased, MEM_ERASED_ADDR, sizeof(MEM_erased));
}
uint8_t memory_read_erased(void)
{
    memory_byte_flag(NULL, &MEM_erased, MEM_ERASED_ADDR, sizeof(MEM_erased));
    return MEM_erased;
}
uint8_t memory_report_erased(void)
{
    return MEM_erased;
}


uint16_t memory_access_err_count(const uint8_t access)
{
    uint16_t err_count = 0xF0F0;
    if (access == DBB_ACCESS_ITERATE) {
        memory_byte_flag(NULL, (uint8_t *)&MEM_access_err, MEM_ACCESS_ERR_ADDR,
                         sizeof(MEM_access_err));
        err_count = MEM_access_err + 1;
    } else if (access == DBB_ACCESS_INITIALIZE) {
        err_count = 0;
    } else {
        err_count = COMMANDER_MAX_ATTEMPTS; // corrupted input
    }

    // Force reset after too many failed attempts
    if (err_count >= COMMANDER_MAX_ATTEMPTS) {
        commander_force_reset();
    } else {
        memory_byte_flag((uint8_t *)&err_count, (uint8_t *)&MEM_access_err,
                         MEM_ACCESS_ERR_ADDR, sizeof(MEM_access_err));
    }
    return err_count;
}
uint16_t memory_read_access_err_count(void)
{
    memory_byte_flag(NULL, (uint8_t *)&MEM_access_err, MEM_ACCESS_ERR_ADDR,
                     sizeof(MEM_access_err));
    return MEM_access_err;
}
uint16_t memory_report_access_err_count(void)
{
    return MEM_access_err;
}


uint16_t memory_pin_err_count(const uint8_t access)
{
    uint16_t err_count = 0xF0F0;
    if (access == DBB_ACCESS_ITERATE) {
        memory_byte_flag(NULL, (uint8_t *)&MEM_pin_err, MEM_PIN_ERR_ADDR, sizeof(MEM_pin_err));
        err_count = MEM_pin_err + 1;
    } else if (access == DBB_ACCESS_INITIALIZE) {
        err_count = 0;
    } else {
        err_count = COMMANDER_MAX_ATTEMPTS; // corrupted input
    }

    // Force reset after too many failed attempts
    if (err_count >= COMMANDER_MAX_ATTEMPTS) {
        commander_force_reset();
    } else {
        memory_byte_flag((uint8_t *)&err_count, (uint8_t *)&MEM_pin_err, MEM_PIN_ERR_ADDR,
                         sizeof(MEM_pin_err));
    }
    return err_count;
}
uint16_t memory_read_pin_err_count(void)
{
    memory_byte_flag(NULL, (uint8_t *)&MEM_pin_err, MEM_PIN_ERR_ADDR, sizeof(MEM_pin_err));
    return MEM_pin_err;
}


uint32_t memory_u2f_count_iter(void)
{
    uint32_t c;
    memory_u2f_count_read();
    c = MEM_u2f_count + 1;
    memory_eeprom((uint8_t *)&c, (uint8_t *)&MEM_u2f_count, MEM_U2F_COUNT_ADDR,
                  sizeof(MEM_u2f_count));
    return MEM_u2f_count;
}
void memory_u2f_count_set(uint32_t c)
{
    memory_eeprom((uint8_t *)&c, (uint8_t *)&MEM_u2f_count, MEM_U2F_COUNT_ADDR,
                  sizeof(MEM_u2f_count));
}
uint32_t memory_u2f_count_read(void)
{
    memory_eeprom(NULL, (uint8_t *)&MEM_u2f_count, MEM_U2F_COUNT_ADDR, sizeof(MEM_u2f_count));
    return MEM_u2f_count;
}


void memory_write_ext_flags(uint32_t flags)
{
    memory_byte_flag((uint8_t *)&flags, (uint8_t *)&MEM_ext_flags, MEM_EXT_FLAGS_ADDR,
                     sizeof(MEM_ext_flags));
}
uint32_t memory_read_ext_flags(void)
{
    memory_byte_flag(NULL, (uint8_t *)&MEM_ext_flags, MEM_EXT_FLAGS_ADDR,
                     sizeof(MEM_ext_flags));
    return MEM_ext_flags;
}
uint32_t memory_report_ext_flags(void)
{
    return MEM_ext_flags;
}
