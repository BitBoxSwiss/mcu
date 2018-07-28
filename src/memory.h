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


#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <stdint.h>

#define MEM_PAGE_LEN      32

// User Zones: 0x0000 to 0x0FFF
// Do NOT change address locations.
// Otherwise problems will occur after a firmware update.
#define MEM_ERASED_ADDR                 0x0000// (uint8_t)  Zone 0
#define MEM_SETUP_ADDR                  0x0002// (uint8_t)
#define MEM_ACCESS_ERR_ADDR             0x0004// (uint16_t)
#define MEM_PIN_ERR_ADDR                0x0006// (uint16_t)
#define MEM_UNLOCKED_ADDR               0x0008// (uint8_t)
#define MEM_EXT_FLAGS_ADDR              0x000A// (uint32_t) 32 possible extension flags
#define MEM_U2F_COUNT_ADDR              0x0010// (uint32_t)
#define MEM_NAME_ADDR                   0x0100// (32 bytes) Zone 1
#define MEM_MASTER_BIP32_ADDR           0x0200
#define MEM_MASTER_BIP32_CHAIN_ADDR     0x0300
#define MEM_AESKEY_STAND_ADDR           0x0400
#define MEM_AESKEY_VERIFY_ADDR          0x0500
#define MEM_AESKEY_Z6_ADDR              0x0600// Zone 6 reserved first 32*4 bytes
#define MEM_AESKEY_Z7_ADDR              0x0700// Zone 7 reserved
#define MEM_AESKEY_HIDDEN_ADDR          0x0800
#define MEM_MASTER_ENTROPY_ADDR         0x0900
#define MEM_MASTER_U2F_ADDR             0x0A00
#define MEM_HIDDEN_BIP32_ADDR           0x0B00
#define MEM_HIDDEN_BIP32_CHAIN_ADDR     0x0B80


// Extension flags
#define MEM_EXT_MASK_U2F         0x00000001// Mask of bit to enable (1) or disable (0) U2F functions 
// Will override and disable U2F_HIJACK bit when disabled
#define MEM_EXT_MASK_U2F_HIJACK  0x00000002// Mask of bit to enable (1) or disable (0) U2F_HIJACK interface


// Default settings
#define DEFAULT_unlocked  0xFF
#define DEFAULT_erased    0xFF
#define DEFAULT_setup     0xFF
#define DEFAULT_u2f_count 0xFFFFFFFF
#define DEFAULT_ext_flags 0xFFFFFFFF// U2F and U2F_hijack enabled by default


typedef enum PASSWORD_ID {
    PASSWORD_STAND,
    PASSWORD_HIDDEN,
    PASSWORD_VERIFY,
    PASSWORD_NONE  /* keep last */
} PASSWORD_ID;


void memory_setup(void);
void memory_reset_u2f(void);
void memory_reset_hww(void);
void memory_erase_hww_seed(void);
void memory_random_password(PASSWORD_ID id);
void memory_clear(void);

void memory_active_key_set(uint8_t *key);
uint8_t *memory_active_key_get(void);
uint8_t memory_write_aeskey(const char *password, int len, PASSWORD_ID id);
void memory_read_aeskeys(void);
uint8_t *memory_report_aeskey(PASSWORD_ID id);
uint8_t *memory_report_user_entropy(void);
uint8_t *memory_name(const char *name);
uint8_t *memory_hidden_hww(const uint8_t *master_priv_key);
uint8_t *memory_hidden_hww_chaincode(const uint8_t *chain_code);
uint8_t *memory_master_hww(const uint8_t *master_priv_key);
uint8_t *memory_master_hww_chaincode(const uint8_t *chain_code);
uint8_t *memory_master_hww_entropy(const uint8_t *master_entropy);
uint8_t *memory_master_u2f(const uint8_t *master_u2f);
uint8_t *memory_report_master_u2f(void);

uint8_t *memory_read_memseed(void);
uint8_t memory_read_erased(void);
uint8_t memory_report_erased(void);
uint8_t memory_report_setup(void);
uint8_t memory_read_unlocked(void);
uint32_t memory_read_ext_flags(void);
uint32_t memory_report_ext_flags(void);

void memory_write_memseed(const uint8_t *s);
void memory_write_erased(uint8_t erase);
void memory_write_unlocked(uint8_t u);
void memory_write_ext_flags(uint32_t flags);

uint16_t memory_access_err_count(const uint8_t access);
uint16_t memory_read_access_err_count(void);
uint16_t memory_report_access_err_count(void);
uint16_t memory_pin_err_count(const uint8_t access);
uint16_t memory_read_pin_err_count(void);

uint32_t memory_u2f_count_iter(void);
void memory_u2f_count_set(uint32_t c);
uint32_t memory_u2f_count_read(void);


#endif  // _MEMORY_H_
