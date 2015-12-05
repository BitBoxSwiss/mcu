/*

 The MIT License (MIT)

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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "commander.h"
#include "memory.h"
#include "random.h"
#include "utils.h"
#include "flags.h"
#include "sha2.h"
#ifndef TESTING
#include "ataes132.h"
#include <gpio.h>
#include <delay.h>
#include <ioport.h>
#endif


static uint8_t MEM_unlocked = DEFAULT_unlocked;
static uint8_t MEM_erased = DEFAULT_erased;
static uint8_t MEM_setup = DEFAULT_setup;
static uint16_t MEM_access_err = DEFAULT_access_err;

__extension__ static uint8_t MEM_aeskey_2FA[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_stand[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_crypt[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_verify[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_memory[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_name[] = {[0 ... MEM_PAGE_LEN - 1] = '0'};
__extension__ static uint8_t MEM_master[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_master_chain[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};

__extension__ const uint8_t MEM_PAGE_ERASE[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ const uint16_t MEM_PAGE_ERASE_2X[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFFFF};


static void memory_mempass(void)
{
    uint8_t mempass[32];
    memset(mempass, 0, sizeof(mempass));
    // Encrypt data saved to memory using an AES key obfuscated by the
    // bootloader bytes.
#ifndef TESTING
    sha256_Raw((uint8_t *)(IFLASH0_ADDR), FLASH_BOOT_LEN, mempass);
#endif
    sha256_Raw(mempass, 32, mempass);
    memory_write_aeskey(utils_uint8_to_hex(mempass, sizeof(mempass)), sizeof(mempass) * 2,
                        PASSWORD_MEMORY);
    memset(mempass, 0, sizeof(mempass));
    utils_clear_buffers();
}


static void memory_create_verifypass(void)
{
    uint8_t number[16] = {0};
    random_bytes(number, sizeof(number), 0);
    memory_write_aeskey(utils_uint8_to_hex(number, sizeof(number)), sizeof(number) * 2,
                        PASSWORD_VERIFY);
    memset(number, 0, sizeof(number));
    utils_clear_buffers();
}


// One-time setup on factory install
int memory_setup(void)
{
    if (memory_read_setup()) {
        memory_erase();
#ifndef TESTING
        // Lock Config Memory:        OP   MODE  PARAMETER1  PARAMETER2
        const uint8_t ataes_cmd[] = {0x0D, 0x02, 0x00, 0x00, 0x00, 0x00};
        // Return packet [Count(1) || Return Code (1) || CRC (2)]
        uint8_t ataes_ret[4] = {0};
        if (ataes_process(ataes_cmd, sizeof(ataes_cmd), ataes_ret, 4) != DBB_OK) {
            return DBB_ERROR;
        }
#endif
        memory_write_setup(0x00);
    } else {
        memory_mempass();
    }
    return DBB_OK;
}


void memory_erase_seed(void)
{
    memory_chaincode(MEM_PAGE_ERASE);
    memory_master(MEM_PAGE_ERASE);
}


void memory_erase(void)
{
    memory_mempass();
    memory_create_verifypass();
    memory_write_aeskey((const char *)MEM_PAGE_ERASE, MEM_PAGE_LEN, PASSWORD_STAND);
    memory_write_aeskey((const char *)MEM_PAGE_ERASE, MEM_PAGE_LEN, PASSWORD_CRYPT);
    memory_erase_seed();
    memory_name("Digital Bitbox");
    memory_write_erased(DEFAULT_erased);
    memory_write_unlocked(DEFAULT_unlocked);
    memory_access_err_count(DEFAULT_access_err);
}


void memory_clear(void)
{
#ifndef TESTING
    // Zero important variables in RAM on embedded MCU.
    // Do not clear for testing routines (i.e. not embedded).
    memcpy(MEM_name, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_2FA, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_stand, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_crypt, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_verify, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master_chain, MEM_PAGE_ERASE, MEM_PAGE_LEN);
#endif
}


static int memory_eeprom(uint8_t *write_b, uint8_t *read_b, const int32_t addr,
                         const uint16_t len)
{
#ifndef TESTING
    // read current memory
    if (ataes_eeprom(len, addr, read_b, NULL) != DBB_OK) {
        commander_fill_report(cmd_str(CMD_ataes), NULL, DBB_ERR_MEM_ATAES);
        return DBB_ERROR;
    }
#endif
    if (write_b) {
#ifndef TESTING
        // skip writing if memory does not change
        if (read_b) {
            if (!memcmp(read_b, write_b, len)) {
                return DBB_OK;
            }
        }
        if (ataes_eeprom(len, addr, read_b, write_b) != DBB_OK) {
            commander_fill_report(cmd_str(CMD_ataes), NULL, DBB_ERR_MEM_ATAES);
            return DBB_ERROR;
        }
        if (read_b) {
            if (!memcmp(write_b, read_b, len)) {
                return DBB_OK;
            } else {
                // error
                if (len > 2) {
                    memcpy(read_b, MEM_PAGE_ERASE, len);
                }
                return DBB_ERROR;
            }
        }
#else
        memcpy(read_b, write_b, len);
        (void) addr;
        return DBB_OK;
#endif
    }
    return DBB_OK;
}


// Encrypted storage
static int memory_eeprom_crypt(const uint8_t *write_b, uint8_t *read_b,
                               const int32_t addr)
{
    int enc_len, dec_len;
    char *enc, *dec, enc_r[MEM_PAGE_LEN * 4 + 1] = {0};
    if (read_b) {
        enc = aes_cbc_b64_encrypt((unsigned char *)utils_uint8_to_hex(read_b, MEM_PAGE_LEN),
                                  MEM_PAGE_LEN * 2, &enc_len, PASSWORD_MEMORY);
        if (!enc) {
            goto err;
        }
        snprintf(enc_r, sizeof(enc_r), "%.*s", enc_len, enc);
        free(enc);
    }

    if (write_b) {
        char enc_w[MEM_PAGE_LEN * 4 + 1] = {0};
        enc = aes_cbc_b64_encrypt((unsigned char *)utils_uint8_to_hex(write_b, MEM_PAGE_LEN),
                                  MEM_PAGE_LEN * 2, &enc_len, PASSWORD_MEMORY);
        if (!enc) {
            goto err;
        }
        snprintf(enc_w, sizeof(enc_w), "%.*s", enc_len, enc);
        free(enc);
        if (memory_eeprom((uint8_t *)enc_w, (uint8_t *)enc_r, addr,
                          MEM_PAGE_LEN) == DBB_ERROR) {
            goto err;
        }
        if (memory_eeprom((uint8_t *)enc_w + MEM_PAGE_LEN, (uint8_t *)enc_r + MEM_PAGE_LEN,
                          addr + MEM_PAGE_LEN, MEM_PAGE_LEN) == DBB_ERROR) {
            goto err;
        }
        if (memory_eeprom((uint8_t *)enc_w + MEM_PAGE_LEN * 2,
                          (uint8_t *)enc_r + MEM_PAGE_LEN * 2, addr + MEM_PAGE_LEN * 2,
                          MEM_PAGE_LEN) == DBB_ERROR) {
            goto err;
        }
        if (memory_eeprom((uint8_t *)enc_w + MEM_PAGE_LEN * 3,
                          (uint8_t *)enc_r + MEM_PAGE_LEN * 3, addr + MEM_PAGE_LEN * 3,
                          MEM_PAGE_LEN) == DBB_ERROR) {
            goto err;
        }
    } else {
        if (memory_eeprom(NULL, (uint8_t *)enc_r, addr, MEM_PAGE_LEN) == DBB_ERROR) {
            goto err;
        }
        if (memory_eeprom(NULL, (uint8_t *)enc_r + MEM_PAGE_LEN, addr + MEM_PAGE_LEN,
                          MEM_PAGE_LEN) == DBB_ERROR) {
            goto err;
        }
        if (memory_eeprom(NULL, (uint8_t *)enc_r + MEM_PAGE_LEN * 2, addr + MEM_PAGE_LEN * 2,
                          MEM_PAGE_LEN) == DBB_ERROR) {
            goto err;
        }
        if (memory_eeprom(NULL, (uint8_t *)enc_r + MEM_PAGE_LEN * 3, addr + MEM_PAGE_LEN * 3,
                          MEM_PAGE_LEN) == DBB_ERROR) {
            goto err;
        }
    }

    dec = aes_cbc_b64_decrypt((unsigned char *)enc_r, MEM_PAGE_LEN * 4, &dec_len,
                              PASSWORD_MEMORY);
    if (!dec) {
        goto err;
    }
    memcpy(read_b, utils_hex_to_uint8(dec), MEM_PAGE_LEN);
    memset(dec, 0, dec_len);
    free(dec);

    utils_clear_buffers();
    return DBB_OK;
err:
    utils_clear_buffers();
    return DBB_ERROR;
}


uint8_t *memory_name(const char *name)
{
    uint8_t name_b[MEM_PAGE_LEN] = {0};
    if (strlens(name)) {
        snprintf((char *)name_b, MEM_PAGE_LEN, "%s", name);
        memory_eeprom(name_b, MEM_name, MEM_NAME_ADDR, MEM_PAGE_LEN);
    } else {
        memory_eeprom(NULL, MEM_name, MEM_NAME_ADDR, MEM_PAGE_LEN);
    }
    return MEM_name;
}


uint8_t *memory_master(const uint8_t *master)
{
    memory_eeprom_crypt(master, MEM_master, MEM_MASTER_BIP32_ADDR);
    return MEM_master;
}


uint8_t *memory_chaincode(const uint8_t *chain)
{
    memory_eeprom_crypt(chain, MEM_master_chain, MEM_MASTER_BIP32_CHAIN_ADDR);
    return MEM_master_chain;
}


int memory_aeskey_is_erased(PASSWORD_ID id)
{
    uint8_t mem_aeskey_erased[MEM_PAGE_LEN];
    sha256_Raw((const uint8_t *)MEM_PAGE_ERASE, MEM_PAGE_LEN, mem_aeskey_erased);
    sha256_Raw(mem_aeskey_erased, MEM_PAGE_LEN, mem_aeskey_erased);

    if (memcmp(memory_report_aeskey(id), mem_aeskey_erased, 32)) {
        return DBB_MEM_NOT_ERASED;
    } else {
        return DBB_MEM_ERASED;
    }
}


int memory_write_aeskey(const char *password, int len, PASSWORD_ID id)
{
    int ret = DBB_ERROR;
    uint8_t password_b[MEM_PAGE_LEN];
    memset(password_b, 0, MEM_PAGE_LEN);

    if (len < PASSWORD_LEN_MIN || strlens(password) < PASSWORD_LEN_MIN) {
        return DBB_ERR_IO_PASSWORD_LEN;
    }

    sha256_Raw((const uint8_t *)password, len, password_b);
    sha256_Raw(password_b, MEM_PAGE_LEN, password_b);

    switch ((int)id) {
        case PASSWORD_MEMORY:
            memcpy(MEM_aeskey_memory, password_b, MEM_PAGE_LEN);
            ret = DBB_OK;
            break;
        case PASSWORD_2FA:
            memcpy(MEM_aeskey_2FA, password_b, MEM_PAGE_LEN);
            ret = DBB_OK;
            break;
        case PASSWORD_STAND:
            ret = memory_eeprom_crypt(password_b, MEM_aeskey_stand, MEM_AESKEY_STAND_ADDR);
            break;
        case PASSWORD_CRYPT:
            ret = memory_eeprom_crypt(password_b, MEM_aeskey_crypt, MEM_AESKEY_CRYPT_ADDR);
            break;
        case PASSWORD_VERIFY:
            ret = memory_eeprom_crypt(password_b, MEM_aeskey_verify, MEM_AESKEY_VERIFY_ADDR);
            break;
        default: {
            /* never reached */
        }
    }

    memset(password_b, 0, MEM_PAGE_LEN);
    if (ret == DBB_OK) {
        return DBB_OK;
    } else {
        return DBB_ERR_MEM_ATAES;
    }
}

void memory_load_aeskeys(void)
{
    memory_eeprom_crypt(NULL, MEM_aeskey_stand, MEM_AESKEY_STAND_ADDR);
    memory_eeprom_crypt(NULL, MEM_aeskey_crypt, MEM_AESKEY_CRYPT_ADDR);
    memory_eeprom_crypt(NULL, MEM_aeskey_verify, MEM_AESKEY_VERIFY_ADDR);
}

uint8_t *memory_report_aeskey(PASSWORD_ID id)
{
    switch ((int)id) {
        case PASSWORD_MEMORY:
            return MEM_aeskey_memory;
        case PASSWORD_2FA:
            return MEM_aeskey_2FA;
        case PASSWORD_STAND:
            return MEM_aeskey_stand;
        case PASSWORD_CRYPT:
            return MEM_aeskey_crypt;
        case PASSWORD_VERIFY:
            return MEM_aeskey_verify;
        default:
            return 0;
    }
}


void memory_write_setup(uint8_t setup)
{
    memory_eeprom(&setup, &MEM_setup, MEM_SETUP_ADDR, 1);
}
uint8_t memory_read_setup(void)
{
    memory_eeprom(NULL, &MEM_setup, MEM_SETUP_ADDR, 1);
    return MEM_setup;
}


void memory_write_unlocked(uint8_t u)
{
    memory_eeprom(&u, &MEM_unlocked, MEM_UNLOCKED_ADDR, 1);
}
uint8_t memory_read_unlocked(void)
{
    memory_eeprom(NULL, &MEM_unlocked, MEM_UNLOCKED_ADDR, 1);
    return MEM_unlocked;
}


void memory_write_erased(uint8_t erased)
{
    memory_eeprom(&erased, &MEM_erased, MEM_ERASED_ADDR, 1);
}
uint8_t memory_read_erased(void)
{
    memory_eeprom(NULL, &MEM_erased, MEM_ERASED_ADDR, 1);
    return MEM_erased;
}


// Initialize or increment non-volatile err counter
uint16_t memory_access_err_count(const uint8_t access)
{
    uint16_t err_count = 0xF0F0;
    if (access == DBB_ACCESS_ITERATE) {
        memory_eeprom(NULL, (uint8_t *)&MEM_access_err, MEM_ACCESS_ERR_ADDR, 2);
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
        memory_eeprom((uint8_t *)&err_count, (uint8_t *)&MEM_access_err, MEM_ACCESS_ERR_ADDR, 2);
    }
    return err_count;
}
uint16_t memory_read_access_err_count(void)
{
    memory_eeprom(NULL, (uint8_t *)&MEM_access_err, MEM_ACCESS_ERR_ADDR, 2);
    return MEM_access_err;
}

