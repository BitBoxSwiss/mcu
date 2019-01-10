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
#define MEM_EXT_MASK_U2F               0x00000001 // Mask of bit to enable (1) or disable (0) U2F functions; will override and disable U2F_HIJACK bit when disabled
#define MEM_EXT_MASK_U2F_HIJACK        0x00000002 // Mask of bit to enable (1) or disable (0) U2F_HIJACK interface
#define MEM_EXT_MASK_NEW_HIDDEN_WALLET 0x00000004 // Mask of bit to enable (1) or disable (0) the new hidden wallet derivation
#define MEM_EXT_MASK_NOTPAIRED         0x00000008 // Mask of bit to disable (1) or enable (0) pairing
// Default settings
#define MEM_DEFAULT_unlocked            0xFF
#define MEM_DEFAULT_erased              0xFF
#define MEM_DEFAULT_setup               0xFF
#define MEM_DEFAULT_u2f_count           0xFFFFFFFF
#define MEM_DEFAULT_ext_flags           0xFFFFFFFF// U2F and U2F_hijack enabled by default
#define MEM_DEFAULT_memory_map_version  0xFFFFFFFF


typedef enum PASSWORD_ID {
    PASSWORD_STAND,
    PASSWORD_HIDDEN,
    TFA_SHARED_SECRET,
    PASSWORD_NONE  /* keep last */
} PASSWORD_ID;


void memory_write_memory_map_version(uint32_t v);
void memory_setup(void);
void memory_update_memory_map(void);
void memory_reset_u2f(void);
void memory_reset_hww(void);
void memory_erase_hww_seed(void);
void memory_random_password(PASSWORD_ID id);
void memory_clear(void);

void memory_active_key_set(uint8_t *key);
uint8_t *memory_active_key_get(void);
uint8_t memory_write_tfa_shared_secret(const uint8_t *secret);
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
