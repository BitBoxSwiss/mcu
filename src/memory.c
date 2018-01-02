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
#include "memory.h"
#include "random.h"
#include "utils.h"
#include "flags.h"
#include "hmac.h"
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
static uint32_t MEM_ext_flags = DEFAULT_ext_flags;
static uint32_t MEM_u2f_count = DEFAULT_u2f_count;
static uint16_t MEM_pin_err = DBB_ACCESS_INITIALIZE;
static uint16_t MEM_access_err = DBB_ACCESS_INITIALIZE;
static uint8_t MEM_session_key_state = MEM_SESSION_KEY_STATE_OFF;

__extension__ static uint8_t MEM_user_entropy[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_session_key[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_session_key_new[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_stand[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_hidden[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_verify[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_master_hww_entropy[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_master_hww_chain[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_master_hww[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_master_u2f[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_name[] = {[0 ... MEM_PAGE_LEN - 1] = '0'};

__extension__ const uint8_t MEM_PAGE_ERASE[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ const uint16_t MEM_PAGE_ERASE_2X[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFFFF};


static uint8_t memory_eeprom(uint8_t *write_b, uint8_t *read_b, const int32_t addr,
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
static uint8_t memory_eeprom_crypt(const uint8_t *write_b, uint8_t *read_b,
                                   const int32_t addr)
{
    int enc_len, dec_len;
    char *enc, *dec, enc_r[MEM_PAGE_LEN * 4 + 1] = {0};
    static uint8_t mempass[MEM_PAGE_LEN];

    // Encrypt data saved to memory using an AES key obfuscated by the
    // bootloader bytes.
    memset(mempass, 0, sizeof(mempass));
#ifndef TESTING
    sha256_Raw((uint8_t *)(FLASH_BOOT_START), FLASH_BOOT_LEN, mempass);
#endif
    sha256_Raw(mempass, MEM_PAGE_LEN, mempass);

    if (read_b) {
        enc = aes_cbc_b64_encrypt((unsigned char *)utils_uint8_to_hex(read_b, MEM_PAGE_LEN),
                                  MEM_PAGE_LEN * 2, &enc_len, mempass);
        if (!enc) {
            goto err;
        }
        snprintf(enc_r, sizeof(enc_r), "%.*s", enc_len, enc);
        free(enc);
    }

    if (write_b) {
        char enc_w[MEM_PAGE_LEN * 4 + 1] = {0};
        enc = aes_cbc_b64_encrypt((unsigned char *)utils_uint8_to_hex(write_b, MEM_PAGE_LEN),
                                  MEM_PAGE_LEN * 2, &enc_len, mempass);
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
                              mempass);
    if (!dec) {
        goto err;
    }
    memcpy(read_b, utils_hex_to_uint8(dec), MEM_PAGE_LEN);
    utils_zero(dec, dec_len);
    free(dec);

    utils_zero(mempass, MEM_PAGE_LEN);
    utils_clear_buffers();
    return DBB_OK;
err:
    utils_zero(mempass, MEM_PAGE_LEN);
    utils_clear_buffers();
    return DBB_ERROR;
}


static void memory_write_setup(uint8_t setup)
{
    memory_eeprom(&setup, &MEM_setup, MEM_SETUP_ADDR, 1);
}


static uint8_t memory_read_setup(void)
{
    memory_eeprom(NULL, &MEM_setup, MEM_SETUP_ADDR, 1);
    return MEM_setup;
}


uint8_t memory_setup(void)
{
    if (memory_read_setup()) {
        // One-time setup on factory install
#ifndef TESTING
        // Lock Config Memory:        OP   MODE  PARAMETER1  PARAMETER2
        const uint8_t ataes_cmd[] = {0x0D, 0x02, 0x00, 0x00, 0x00, 0x00};
        // Return packet [Count(1) || Return Code (1) || CRC (2)]
        uint8_t ataes_ret[4] = {0};
        if (ataes_process(ataes_cmd, sizeof(ataes_cmd), ataes_ret, 4) != DBB_OK) {
            return DBB_ERROR;
        }
#endif
        uint32_t c = 0x00000000;
        memory_reset_hww();
        memory_reset_u2f();
        memory_eeprom((uint8_t *)&c, (uint8_t *)&MEM_u2f_count, MEM_U2F_COUNT_ADDR, 4);
        memory_write_setup(0x00);
    } else {
        memory_read_ext_flags();
        memory_read_aeskey(PASSWORD_VERIFY);
        memory_eeprom(NULL, &MEM_erased, MEM_ERASED_ADDR, 1);
        memory_master_u2f(NULL);// Load cache so that U2F speed is fast enough
        memory_read_access_err_count();// Load cache
        memory_u2f_count_read();
    }
    memory_session_key_update();
    memory_session_key_set(NULL);
    memory_session_key_off();
    return DBB_OK;
}


void memory_erase_hww_seed(void)
{
    memory_master_hww_entropy(MEM_PAGE_ERASE);
    memory_master_hww_chaincode(MEM_PAGE_ERASE);
    memory_master_hww(MEM_PAGE_ERASE);
}


void memory_reset_hww(void)
{
    memory_random_password(PASSWORD_STAND);
    memory_random_password(PASSWORD_VERIFY);
    memory_random_password(PASSWORD_HIDDEN);
    memory_erase_hww_seed();
    memory_name(DEVICE_DEFAULT_NAME);
    memory_write_erased(DEFAULT_erased);
    memory_write_unlocked(DEFAULT_unlocked);
    memory_write_ext_flags(DEFAULT_ext_flags);
    memory_access_err_count(DBB_ACCESS_INITIALIZE);
    memory_pin_err_count(DBB_ACCESS_INITIALIZE);
    memory_session_key_off();
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
#ifndef TESTING
    // Zero important variables in RAM on embedded MCU.
    // Do not clear for testing routines (i.e. not embedded).
    memcpy(MEM_master_hww_chain, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master_hww, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master_hww_entropy, MEM_PAGE_ERASE, MEM_PAGE_LEN);
#endif
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


uint8_t *memory_master_hww(const uint8_t *master)
{
    memory_eeprom_crypt(master, MEM_master_hww, MEM_MASTER_BIP32_ADDR);
    return MEM_master_hww;
}


uint8_t *memory_master_hww_chaincode(const uint8_t *chain)
{
    memory_eeprom_crypt(chain, MEM_master_hww_chain, MEM_MASTER_BIP32_CHAIN_ADDR);
    return MEM_master_hww_chain;
}


uint8_t *memory_master_hww_entropy(const uint8_t *master_entropy)
{
    memory_eeprom_crypt(master_entropy, MEM_master_hww_entropy, MEM_MASTER_ENTROPY_ADDR);
    return MEM_master_hww_entropy;
}


uint8_t *memory_master_u2f(const uint8_t *master_u2f)
{
    memory_eeprom_crypt(master_u2f, MEM_master_u2f, MEM_MASTER_U2F_ADDR);
    return MEM_master_u2f;
}


uint8_t *memory_report_master_u2f(void)
{
    return MEM_master_u2f;
}


void memory_clear_passwords(void)
{
    uint8_t number[32] = {0};
    random_bytes(number, sizeof(number), 0);
#ifndef TESTING
    memcpy(MEM_aeskey_stand, number, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_hidden, number, MEM_PAGE_LEN);
#endif
}


uint8_t *memory_session_key_update(void)
{
    MEM_session_key_state = MEM_SESSION_KEY_STATE_UPDATING;
    random_bytes(MEM_session_key_new, MEM_PAGE_LEN, 0);
    return MEM_session_key_new;
}


void memory_session_key_off(void)
{
    MEM_session_key_state = MEM_SESSION_KEY_STATE_OFF;
}


void memory_session_key_set(uint8_t *key)
{
    if (key) {
        memcpy(MEM_session_key, key, MEM_PAGE_LEN);
        MEM_session_key_state = MEM_SESSION_KEY_STATE_STATIC;
    } else {
        if (MEM_session_key_state == MEM_SESSION_KEY_STATE_UPDATING) {
            memcpy(MEM_session_key, MEM_session_key_new, MEM_PAGE_LEN);
        } else {
            random_bytes(MEM_session_key, MEM_PAGE_LEN, 0);
        }
        MEM_session_key_state = MEM_SESSION_KEY_STATE_EPHEMERAL;
    }
}


uint8_t *memory_session_key_report(void)
{
    return MEM_session_key;
}


uint8_t memory_session_key_get_state(void)
{
    return MEM_session_key_state;
}


uint8_t memory_write_aeskey(const char *password, int len, PASSWORD_ID id)
{
    uint8_t ret = DBB_ERROR;
    uint8_t password_b[MEM_PAGE_LEN];
    memset(password_b, 0, MEM_PAGE_LEN);

    if (len < PASSWORD_LEN_MIN || strlens(password) < PASSWORD_LEN_MIN) {
        return DBB_ERR_IO_PASSWORD_LEN;
    }

    sha256_Raw((const uint8_t *)password, len, password_b);
    sha256_Raw(password_b, MEM_PAGE_LEN, password_b);

    switch ((int)id) {
        case PASSWORD_STAND:
            ret = memory_eeprom_crypt(password_b, MEM_aeskey_stand, MEM_AESKEY_STAND_ADDR);
            sha256_Raw(password_b, MEM_PAGE_LEN, password_b);
            memcpy(MEM_user_entropy, password_b, MEM_PAGE_LEN);
            break;
        case PASSWORD_HIDDEN:
            ret = memory_eeprom_crypt(password_b, MEM_aeskey_hidden, MEM_AESKEY_HIDDEN_ADDR);
            break;
        case PASSWORD_VERIFY:
            ret = memory_eeprom_crypt(password_b, MEM_aeskey_verify, MEM_AESKEY_VERIFY_ADDR);
            break;
        default: {
            /* never reached */
        }
    }

    utils_zero(password_b, MEM_PAGE_LEN);
    if (ret == DBB_OK) {
        return DBB_OK;
    } else {
        return DBB_ERR_MEM_ATAES;
    }
}


uint8_t *memory_read_aeskey(PASSWORD_ID id)
{
    switch ((int)id) {
        case PASSWORD_STAND:
            memory_eeprom_crypt(NULL, MEM_aeskey_stand, MEM_AESKEY_STAND_ADDR);
            return MEM_aeskey_stand;
        case PASSWORD_HIDDEN:
            memory_eeprom_crypt(NULL, MEM_aeskey_hidden, MEM_AESKEY_HIDDEN_ADDR);
            return MEM_aeskey_hidden;
        case PASSWORD_VERIFY:
            memory_eeprom_crypt(NULL, MEM_aeskey_verify, MEM_AESKEY_VERIFY_ADDR);
            return MEM_aeskey_verify;
        default:
            return NULL;
    }
}


uint8_t *memory_report_verification_key(void)
{
    return MEM_aeskey_verify;
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
uint8_t memory_report_erased(void)
{
    return MEM_erased;
}


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
uint16_t memory_report_access_err_count(void)
{
    return MEM_access_err;
}


uint16_t memory_pin_err_count(const uint8_t access)
{
    uint16_t err_count = 0xF0F0;
    if (access == DBB_ACCESS_ITERATE) {
        memory_eeprom(NULL, (uint8_t *)&MEM_pin_err, MEM_PIN_ERR_ADDR, 2);
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
        memory_eeprom((uint8_t *)&err_count, (uint8_t *)&MEM_pin_err, MEM_PIN_ERR_ADDR, 2);
    }
    return err_count;
}
uint16_t memory_read_pin_err_count(void)
{
    memory_eeprom(NULL, (uint8_t *)&MEM_pin_err, MEM_PIN_ERR_ADDR, 2);
    return MEM_pin_err;
}


uint32_t memory_u2f_count_iter(void)
{
    uint32_t c;
    memory_u2f_count_read();
    c = MEM_u2f_count + 1;
    memory_eeprom((uint8_t *)&c, (uint8_t *)&MEM_u2f_count, MEM_U2F_COUNT_ADDR, 4);
    return MEM_u2f_count;
}
uint32_t memory_u2f_count_read(void)
{
    memory_eeprom(NULL, (uint8_t *)&MEM_u2f_count, MEM_U2F_COUNT_ADDR, 4);
    return MEM_u2f_count;
}


void memory_write_ext_flags(uint32_t flags)
{
    memory_eeprom((uint8_t *)&flags, (uint8_t *)&MEM_ext_flags, MEM_EXT_FLAGS_ADDR, 4);
}
uint32_t memory_read_ext_flags(void)
{
    memory_eeprom(NULL, (uint8_t *)&MEM_ext_flags, MEM_EXT_FLAGS_ADDR, 4);
    return MEM_ext_flags;
}
uint32_t memory_report_ext_flags(void)
{
    return MEM_ext_flags;
}
