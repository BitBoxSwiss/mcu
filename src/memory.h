/*

 The MIT License (MIT)

 Copyright (c) 2015-2016 Douglas J. Bakkum

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
#define MEM_ERASED_ADDR                 0x0000// Zone 0
#define MEM_SETUP_ADDR                  0x0002
#define MEM_ACCESS_ERR_ADDR             0x0004
#define MEM_PIN_ERR_ADDR                0x0006
#define MEM_UNLOCKED_ADDR               0x0008
#define MEM_EXT_FLAGS_ADDR              0x000A// (uint32_t) 32 possible extension flags
#define MEM_U2F_COUNT_ADDR              0x0010// (uint32_t)
#define MEM_NAME_ADDR                   0x0100// Zone 1
#define MEM_MASTER_BIP32_ADDR           0x0200
#define MEM_MASTER_BIP32_CHAIN_ADDR     0x0300
#define MEM_AESKEY_STAND_ADDR           0x0400
#define MEM_AESKEY_VERIFY_ADDR          0x0500
#define MEM_AESKEY_CRYPT_ADDR           0x0600
#define MEM_AESKEY_HIDDEN_ADDR          0x0800// Zone 7 reserved
#define MEM_MASTER_ENTROPY_ADDR         0x0900


// Extension flags
#define MEM_EXT_FLAG_U2F  0x00000001// Flag to enable or disabled U2F


// Default settings
#define DEFAULT_unlocked  0xFF
#define DEFAULT_erased    0xFF
#define DEFAULT_setup     0xFF
#define DEFAULT_u2f_count 0xFFFFFFFF
#define DEFAULT_ext_flags (0xFFFFFFFF & ~MEM_EXT_FLAG_U2F)// Enable U2F by default


typedef enum PASSWORD_ID {
    PASSWORD_STAND,
    PASSWORD_HIDDEN,
    PASSWORD_VERIFY,
    PASSWORD_MEMORY,
    PASSWORD_CRYPT,
    PASSWORD_NONE  /* keep last */
} PASSWORD_ID;


int memory_setup(void);
void memory_erase(void);
void memory_erase_seed(void);
void memory_random_password(PASSWORD_ID id);
void memory_clear(void);

int memory_aeskey_is_erased(PASSWORD_ID id);
int memory_write_aeskey(const char *password, int len, PASSWORD_ID id);
uint8_t *memory_report_aeskey(PASSWORD_ID id);
uint8_t *memory_name(const char *name);
uint8_t *memory_master(const uint8_t *master_priv_key);
uint8_t *memory_chaincode(const uint8_t *chain_code);
uint8_t *memory_master_entropy(const uint8_t *master_entropy);
uint8_t *memory_master_u2f(void);

uint8_t *memory_read_memseed(void);
uint8_t memory_read_erased(void);
uint8_t memory_report_erased(void);
uint8_t memory_read_setup(void);
uint8_t memory_read_unlocked(void);
uint32_t memory_read_ext_flags(void);
uint32_t memory_report_ext_flags(void);

void memory_write_memseed(const uint8_t *s);
void memory_write_erased(uint8_t erase);
void memory_write_setup(uint8_t setup);
void memory_write_unlocked(uint8_t u);
void memory_write_ext_flags(uint32_t flags);

uint16_t memory_access_err_count(const uint8_t access);
uint16_t memory_read_access_err_count(void);
uint16_t memory_pin_err_count(const uint8_t access);
uint16_t memory_read_pin_err_count(void);

uint32_t memory_u2f_count_iter(void);
uint32_t memory_u2f_count_read(void);


#endif  // _MEMORY_H_
