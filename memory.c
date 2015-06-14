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

#include "commander.h"
#include "random.h"
#include "memory.h"
#include "utils.h"
#include "flags.h"
#include "sha2.h"
#ifndef TESTING
#include "ataes132.h"
#include <gpio.h>
#include <delay.h>
#include <ioport.h>
#endif


static uint8_t MEM_unlocked_ = DEFAULT_unlocked_;
static uint8_t MEM_erased_ = DEFAULT_erased_;
static uint8_t MEM_setup_ = DEFAULT_setup_;
static uint8_t MEM_led_ = DEFAULT_led_;
static uint16_t MEM_access_err_ = DEFAULT_access_err_;
static uint16_t MEM_touch_thresh_ = DEFAULT_touch_timeout_;
static uint16_t MEM_touch_timeout_ = DEFAULT_touch_timeout_;

static uint8_t MEM_aeskey_2FA_[] = {[0 ... MEM_PAGE_LEN] = 0xFF};
static uint8_t MEM_aeskey_stand_[] = {[0 ... MEM_PAGE_LEN] = 0xFF};
static uint8_t MEM_aeskey_crypt_[] = {[0 ... MEM_PAGE_LEN] = 0xFF};
static uint8_t MEM_aeskey_verify_[] = {[0 ... MEM_PAGE_LEN] = 0xFF};
static uint8_t MEM_aeskey_memory_[] = {[0 ... MEM_PAGE_LEN] = 0xFF};
static uint8_t MEM_name_[] = {[0 ... MEM_PAGE_LEN] = '0'};
static uint8_t MEM_master_[] = {[0 ... MEM_PAGE_LEN] = 0xFF};
static uint8_t MEM_master_chain_[] = {[0 ... MEM_PAGE_LEN] = 0xFF};
static uint16_t MEM_mnemonic_[] = {[0 ... MEM_PAGE_LEN] = 0xFFFF};

const uint8_t MEM_PAGE_ERASE[] = {[0 ... MEM_PAGE_LEN] = 0xFF};
const uint16_t MEM_PAGE_ERASE_2X[] = {[0 ... MEM_PAGE_LEN] = 0xFFFF};


// One-time setup on factory install
void memory_setup(void)
{
    if (memory_read_setup()) {
        memory_erase();
#ifndef TESTING
        // Lock Config Memory:        OP   MODE  PARAMETER1  PARAMETER2
        const uint8_t ataes_cmd[] = {0x0D, 0x02, 0x00, 0x00, 0x00, 0x00};
        // Return packet [Count(1) || Return Code (1) || CRC (2)]
        uint8_t ataes_ret[4] = {0};
        aes_process(ataes_cmd, sizeof(ataes_cmd), ataes_ret, 4);
#endif
        memory_write_setup(0x00);
    } else {
        memory_mempass();
    }
}


void memory_erase(void)
{
    memory_mempass();
    memory_write_aeskey((char *)MEM_PAGE_ERASE, MEM_PAGE_LEN, PASSWORD_STAND);
    memory_write_aeskey((char *)MEM_PAGE_ERASE, MEM_PAGE_LEN, PASSWORD_CRYPT);
    memory_mnemonic(MEM_PAGE_ERASE_2X);
    memory_chaincode(MEM_PAGE_ERASE);
    memory_master(MEM_PAGE_ERASE);
    memory_name("Digital Bitbox");
    memory_write_erased(DEFAULT_erased_);
    memory_write_unlocked(DEFAULT_unlocked_);
    memory_write_touch_timeout(DEFAULT_touch_timeout_);
    memory_write_touch_thresh(DEFAULT_touch_thresh_);
    memory_access_err_count(DEFAULT_access_err_);
    memory_write_led(DEFAULT_led_);
    commander_create_verifypass();
}


void memory_clear_variables(void)
{
#ifndef TESTING
    // Zero important variables in RAM on embedded MCU.
    // Do not clear for testing routines (i.e. not embedded).
    memcpy(MEM_name_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_2FA_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_stand_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_crypt_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_verify_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master_chain_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_mnemonic_, MEM_PAGE_ERASE_2X, MEM_PAGE_LEN*2);
#endif
}


static int memory_eeprom(const uint8_t *write_b, uint8_t *read_b, const int32_t addr, const uint16_t len)
{
#ifndef TESTING
    // read current memory
    aes_eeprom(len, addr, read_b, NULL);
#endif
    if (write_b) {
#ifndef TESTING
        // skip writing if memory does not change
        if (read_b) {
            if (!memcmp(read_b, write_b, len)) {
                return 1;
            }
        }
        aes_eeprom(len, addr, read_b, write_b);
        if (read_b) {
            if (!memcmp(write_b, read_b, len)) {
                return 1;
            } else {
                // error
                if (len>2) {
                    memcpy(read_b, MEM_PAGE_ERASE, len);
                }
                return 0;
            }
        }
#else
        memcpy(read_b, write_b, len);
        (void) addr;
        return 1;
#endif
    }
    return 1;
}


// Encrypted storage
static int memory_eeprom_crypt(const uint8_t *write_b, uint8_t *read_b, const int32_t addr)
{
    int enc_len, dec_len, ret = 1;
    char *enc, *dec, enc_r[MEM_PAGE_LEN * 4 + 1] = {0};
    if (read_b) {
        enc = aes_cbc_b64_encrypt((unsigned char *)utils_uint8_to_hex(read_b, MEM_PAGE_LEN), MEM_PAGE_LEN * 2, &enc_len, PASSWORD_MEMORY);
        memcpy(enc_r, enc, enc_len);
        free(enc);
    }

    if (write_b) {
        char enc_w[MEM_PAGE_LEN * 4 + 1] = {0};
        enc = aes_cbc_b64_encrypt((unsigned char *)utils_uint8_to_hex(write_b, MEM_PAGE_LEN), MEM_PAGE_LEN * 2, &enc_len, PASSWORD_MEMORY);
        memcpy(enc_w, enc, enc_len);
        free(enc);
        ret = ret * memory_eeprom((uint8_t *)enc_w,                    (uint8_t *)enc_r,                    addr,                    MEM_PAGE_LEN);
        ret = ret * memory_eeprom((uint8_t *)enc_w + MEM_PAGE_LEN,     (uint8_t *)enc_r + MEM_PAGE_LEN,     addr + MEM_PAGE_LEN,     MEM_PAGE_LEN);
        ret = ret * memory_eeprom((uint8_t *)enc_w + MEM_PAGE_LEN * 2, (uint8_t *)enc_r + MEM_PAGE_LEN * 2, addr + MEM_PAGE_LEN * 2, MEM_PAGE_LEN);
        ret = ret * memory_eeprom((uint8_t *)enc_w + MEM_PAGE_LEN * 3, (uint8_t *)enc_r + MEM_PAGE_LEN * 3, addr + MEM_PAGE_LEN * 3, MEM_PAGE_LEN);
    } else {
        ret = ret * memory_eeprom(NULL, (uint8_t *)enc_r,                    addr,                    MEM_PAGE_LEN);
        ret = ret * memory_eeprom(NULL, (uint8_t *)enc_r + MEM_PAGE_LEN,     addr + MEM_PAGE_LEN,     MEM_PAGE_LEN);
        ret = ret * memory_eeprom(NULL, (uint8_t *)enc_r + MEM_PAGE_LEN * 2, addr + MEM_PAGE_LEN * 2, MEM_PAGE_LEN);
        ret = ret * memory_eeprom(NULL, (uint8_t *)enc_r + MEM_PAGE_LEN * 3, addr + MEM_PAGE_LEN * 3, MEM_PAGE_LEN);
    }

    dec = aes_cbc_b64_decrypt((unsigned char *)enc_r, MEM_PAGE_LEN * 4, &dec_len, PASSWORD_MEMORY);
    if (dec) {
        memcpy(read_b, utils_hex_to_uint8(dec), MEM_PAGE_LEN);
    } else {
        ret = 0;
    }
    free(dec);
    return ret; // 1 on success
}


void memory_mempass(void)
{
    uint8_t mempass[88] = {0};
#ifndef TESTING
    // Encrypt data saved to memory using an AES key obfuscated by the
    // compilation time and date, which is used to 'randomly' read bytes
    // (i.e. the AES key) from the MCU code in flash memory.
    uint8_t *mp = mempass;
    int r[8] = {0};
    char c[3] = {0};
    sscanf(__TIME__, "%d:%d:%d", &r[0], &r[1], &r[2]);
    sscanf(__DATE__, "%c%c%c %d ", &c[0], &c[1], &c[2], &r[3]);
    r[7] = __LINE__ % 1028;
    r[4] = c[0];
    r[5] = c[1];
    r[6] = c[2];
    memcpy(mp +  0, (uint32_t *)IFLASH0_ADDR + r[0] * r[0], 8);
    memcpy(mp +  8, (uint32_t *)IFLASH0_ADDR + r[0] * r[1], 8);
    memcpy(mp + 16, (uint32_t *)IFLASH0_ADDR + r[0] * r[2], 8);
    memcpy(mp + 24, (uint32_t *)IFLASH0_ADDR + r[1] * r[1], 8);
    memcpy(mp + 32, (uint32_t *)IFLASH0_ADDR + r[1] * r[2], 8);
    memcpy(mp + 40, (uint32_t *)IFLASH0_ADDR + r[2] * r[2], 8);
    memcpy(mp + 48, (uint32_t *)IFLASH0_ADDR + r[0] * r[3], 8);
    memcpy(mp + 56, (uint32_t *)IFLASH0_ADDR + r[0] * r[4], 8);
    memcpy(mp + 64, (uint32_t *)IFLASH0_ADDR + r[0] * r[5], 8);
    memcpy(mp + 72, (uint32_t *)IFLASH0_ADDR + r[0] * r[6], 8);
    memcpy(mp + 80, (uint32_t *)IFLASH0_ADDR + r[2] + r[7], 8);
#endif
    memory_write_aeskey(utils_uint8_to_hex(mempass, sizeof(mempass)), sizeof(mempass) * 2, PASSWORD_MEMORY);
}


uint8_t *memory_name(const char *name)
{
    uint8_t name_b[MEM_PAGE_LEN] = {0};
    if (strlen(name)) {
        memcpy(name_b, name, (strlen(name)>MEM_PAGE_LEN) ? MEM_PAGE_LEN : strlen(name));
        memory_eeprom(name_b, MEM_name_, MEM_NAME_ADDR, MEM_PAGE_LEN);
    } else {
        memory_eeprom(NULL, MEM_name_, MEM_NAME_ADDR, MEM_PAGE_LEN);
    }
    return MEM_name_;
}


uint8_t *memory_master(const uint8_t *master)
{
    memory_eeprom_crypt(master, MEM_master_, MEM_MASTER_BIP32_ADDR);
    return MEM_master_;
}


uint8_t *memory_chaincode(const uint8_t *chain)
{
    memory_eeprom_crypt(chain, MEM_master_chain_, MEM_MASTER_BIP32_CHAIN_ADDR);
    return MEM_master_chain_;
}


uint16_t *memory_mnemonic(const uint16_t *idx)
{
    if (idx) {
        memory_eeprom_crypt((uint8_t *)idx, (uint8_t *)MEM_mnemonic_,
                            MEM_MNEMONIC_BIP32_ADDR_0);
        memory_eeprom_crypt((uint8_t *)idx + MEM_PAGE_LEN,
                            (uint8_t *)MEM_mnemonic_ + MEM_PAGE_LEN,
                            MEM_MNEMONIC_BIP32_ADDR_1);
    } else {
        memory_eeprom_crypt(NULL, (uint8_t *)MEM_mnemonic_,
                            MEM_MNEMONIC_BIP32_ADDR_0);
        memory_eeprom_crypt(NULL, (uint8_t *)MEM_mnemonic_ + MEM_PAGE_LEN,
                            MEM_MNEMONIC_BIP32_ADDR_1);
    }
    return MEM_mnemonic_;
}


int memory_aeskey_is_erased(PASSWORD_ID id)
{
    uint8_t mem_aeskey_erased[MEM_PAGE_LEN];
    sha256_Raw((uint8_t *)MEM_PAGE_ERASE, MEM_PAGE_LEN, mem_aeskey_erased);
    sha256_Raw(mem_aeskey_erased, MEM_PAGE_LEN, mem_aeskey_erased);

    if (memcmp(memory_read_aeskey(id), mem_aeskey_erased, 32)) {
        return NOT_ERASED;
    } else {
        return ERASED;
    }
}


int memory_write_aeskey(const char *password, int len, PASSWORD_ID id)
{
    int ret = 0;
    uint8_t password_b[MEM_PAGE_LEN];
    memset(password_b, 0, MEM_PAGE_LEN);


    if (!password) {
        commander_fill_report("password", FLAG_ERR_PASSWORD_LEN, ERROR);
        return ERROR;
    }

    if (len < PASSWORD_LEN_MIN) {
        commander_fill_report("password", FLAG_ERR_PASSWORD_LEN, ERROR);
        return ERROR;
    }

    if (strlen(password) < PASSWORD_LEN_MIN) {
        commander_fill_report("password", FLAG_ERR_PASSWORD_LEN, ERROR);
        return ERROR;
    }

    sha256_Raw((uint8_t *)password, len, password_b);
    sha256_Raw(password_b, MEM_PAGE_LEN, password_b);

    switch ((int)id) {
    case PASSWORD_MEMORY:
        memcpy(MEM_aeskey_memory_, password_b, MEM_PAGE_LEN);
        ret = 1;
        break;
    case PASSWORD_2FA:
        memcpy(MEM_aeskey_2FA_, password_b, MEM_PAGE_LEN);
        ret = 1;
        break;
    case PASSWORD_STAND:
        ret = memory_eeprom_crypt(password_b, MEM_aeskey_stand_, MEM_AESKEY_STAND_ADDR);
        break;
    case PASSWORD_CRYPT:
        ret = memory_eeprom_crypt(password_b, MEM_aeskey_crypt_, MEM_AESKEY_CRYPT_ADDR);
        break;
    case PASSWORD_VERIFY:
        ret = memory_eeprom_crypt(password_b, MEM_aeskey_verify_, MEM_AESKEY_VERIFY_ADDR);
        break;
    }

    if (ret) {
        return SUCCESS;
    } else {
        commander_fill_report("password", FLAG_ERR_ATAES, ERROR);
        return ERROR;
    }
}

uint8_t *memory_read_aeskey(PASSWORD_ID id)
{
    switch ((int)id) {
    case PASSWORD_MEMORY:
        return MEM_aeskey_memory_;
    case PASSWORD_2FA:
        return MEM_aeskey_2FA_;
    case PASSWORD_STAND:
        memory_eeprom_crypt(NULL, MEM_aeskey_stand_, MEM_AESKEY_STAND_ADDR);
        return MEM_aeskey_stand_;
    case PASSWORD_CRYPT:
        memory_eeprom_crypt(NULL, MEM_aeskey_crypt_, MEM_AESKEY_CRYPT_ADDR);
        return MEM_aeskey_crypt_;
    case PASSWORD_VERIFY:
        memory_eeprom_crypt(NULL, MEM_aeskey_verify_, MEM_AESKEY_VERIFY_ADDR);
        return MEM_aeskey_verify_;
    }
    return 0;
}


void memory_write_setup(const uint8_t setup)
{
    memory_eeprom(&setup, &MEM_setup_, MEM_SETUP_ADDR, 1);
}
uint8_t memory_read_setup(void)
{
    memory_eeprom(NULL, &MEM_setup_, MEM_SETUP_ADDR, 1);
    return MEM_setup_;
}


void memory_write_unlocked(const uint8_t u)
{
    memory_eeprom(&u, &MEM_unlocked_, MEM_UNLOCKED_ADDR, 1);
}
uint8_t memory_read_unlocked(void)
{
    memory_eeprom(NULL, &MEM_unlocked_, MEM_UNLOCKED_ADDR, 1);
    return MEM_unlocked_;
}


void memory_write_erased(const uint8_t erased)
{
    memory_eeprom(&erased, &MEM_erased_, MEM_ERASED_ADDR, 1);
}
uint8_t memory_read_erased(void)
{
    memory_eeprom(NULL, &MEM_erased_, MEM_ERASED_ADDR, 1);
    return MEM_erased_;
}


void memory_write_led(const uint8_t led)
{
    memory_eeprom(&led, &MEM_led_, MEM_LED_ADDR, 1);
}
int memory_read_led(void)
{
    memory_eeprom(NULL, &MEM_led_, MEM_LED_ADDR, 1);
    return MEM_led_;
}


void memory_write_touch_timeout(const uint16_t t)
{
    memory_eeprom((uint8_t *)&t, (uint8_t *)&MEM_touch_timeout_, MEM_TOUCH_TIMEOUT_ADDR, 2);
}
uint16_t memory_read_touch_timeout(void)
{
    memory_eeprom(NULL, (uint8_t *)&MEM_touch_timeout_, MEM_TOUCH_TIMEOUT_ADDR, 2);
    return MEM_touch_timeout_;
}


void memory_write_touch_thresh(const uint16_t t)
{
    memory_eeprom((uint8_t *)&t, (uint8_t *)&MEM_touch_thresh_, MEM_TOUCH_THRESH_ADDR, 2);
}
uint16_t memory_read_touch_thresh(void)
{
    memory_eeprom(NULL, (uint8_t *)&MEM_touch_thresh_, MEM_TOUCH_THRESH_ADDR, 2);
    return MEM_touch_thresh_;
}


// Initialize or increment non-volatile err counter
uint16_t memory_access_err_count(const uint8_t access)
{
    uint16_t err_count = 0xF0F0;
    if (access == ITERATE) {
        memory_eeprom(NULL, (uint8_t *)&MEM_access_err_, MEM_ACCESS_ERR_ADDR, 2);
        err_count = MEM_access_err_ + 1;
    } else if (access == INITIALIZE) {
        err_count = 0;
    } else {
        err_count = COMMANDER_MAX_ATTEMPTS; // corrupted input
    }

    // Force reset after too many failed attempts
    if (err_count >= COMMANDER_MAX_ATTEMPTS) {
        commander_force_reset();
    } else {
        memory_eeprom((uint8_t *)&err_count, (uint8_t *)&MEM_access_err_, MEM_ACCESS_ERR_ADDR, 2);
    }
    return err_count;
}
uint16_t memory_read_access_err_count(void)
{
    memory_eeprom(NULL, (uint8_t *)&MEM_access_err_, MEM_ACCESS_ERR_ADDR, 2);
    return MEM_access_err_;
}

