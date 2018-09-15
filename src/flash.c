/*

 The MIT License (MIT)

 Copyright (c) 2018 Douglas J. Bakkum

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


#include "flash.h"
#include "utils.h"
#ifndef TESTING
#include "mcu.h"
#else
__extension__ static uint8_t flash_usersig_simulation[] = {[0 ... FLASH_USERSIG_SIZE - 1] = 0xFF};
__extension__ static uint8_t flash_sig_area_simulation[] = {[0 ... FLASH_SIG_LEN - 1] = 0xFF};
#endif


#ifdef TESTING
void HardFault_Handler(void)
{
    exit(1);
}

void MemManage_Handler(void)
{
    exit(2);
}
#endif


uint8_t flash_wrapper_read_unique_id(uint32_t *serial, uint32_t len)
{
#ifdef TESTING
    memset(serial, 1, sizeof(uint32_t) * len);
    return 0; // success
#else
    return flash_read_unique_id(serial, len);
#endif
}


uint32_t flash_wrapper_erase_usersig(void)
{
#ifdef TESTING
    memset(flash_usersig_simulation, 0xFF, FLASH_USERSIG_SIZE);
#else
    if (flash_erase_user_signature()) {
        HardFault_Handler();
    }
#endif
    return 0; // success
}


uint32_t flash_wrapper_write_usersig(const void *p_buffer, uint32_t ul_size)
{
#ifdef TESTING
    uint32_t i;
    uint8_t buf[ul_size * sizeof(uint32_t)];
    if (ul_size * sizeof(uint32_t) != FLASH_USERSIG_SIZE) {
        return 1; // error
    }
    memcpy(buf, p_buffer, FLASH_USERSIG_SIZE);
    for (i = 0; i < FLASH_USERSIG_SIZE; i++) {
        // bare-metal write can only change bits to 0b
        flash_usersig_simulation[i] &= buf[i];
    }
#else
    if (flash_write_user_signature(p_buffer, ul_size)) {
        HardFault_Handler();
    }
#endif
    return 0; // success
}


uint32_t flash_wrapper_read_usersig(uint32_t *p_data, uint32_t ul_size)
{
#ifdef TESTING
    if (ul_size * sizeof(uint32_t) > FLASH_USERSIG_SIZE) {
        return 1; // error
    }
    memcpy(p_data, flash_usersig_simulation, ul_size * sizeof(uint32_t));
#else
    if (flash_read_user_signature(p_data, ul_size)) {
        utils_zero(p_data, ul_size);
        HardFault_Handler();
    };
#endif
    return 0; // success
}


uint32_t flash_wrapper_erase_page(uint32_t ul_address, uint8_t uc_page_num)
{
#ifdef TESTING
    if (ul_address != FLASH_SIG_START) {
        return !FLASH_RC_OK;
    }
    if (uc_page_num != IFLASH_ERASE_PAGES_8) {
        return !FLASH_RC_OK;
    }
    memset(flash_sig_area_simulation, 0xFF, FLASH_SIG_LEN);
#else
    if (flash_erase_page(ul_address, uc_page_num) != FLASH_RC_OK) {
        HardFault_Handler();
    };
#endif
    return FLASH_RC_OK; // success
}


uint32_t flash_wrapper_write(uint32_t ul_address, void *p_buffer,
                  uint32_t ul_size, uint32_t ul_erase_flag)
{
#ifdef TESTING
    uint32_t i;
    uint8_t buf[FLASH_SIG_LEN];
    if (ul_erase_flag) {
        flash_wrapper_erase_page(FLASH_SIG_START, IFLASH_ERASE_PAGES_8);
    }
    if (ul_address != FLASH_SIG_START) {
        return !FLASH_RC_OK;
    }
    if (ul_size != FLASH_SIG_LEN) {
        return !FLASH_RC_OK;
    }
    memcpy(buf, p_buffer, FLASH_SIG_LEN);
    for (i = 0; i < FLASH_SIG_LEN; i++) {
        // bare-metal write can only change bits to 0b
        flash_sig_area_simulation[i] &= buf[i];
    }
#else
    if (flash_write(ul_address, p_buffer, ul_size, ul_erase_flag) != FLASH_RC_OK) {
        utils_zero(p_buffer, ul_size);
        HardFault_Handler();
    }
#endif
    return FLASH_RC_OK; // success
}


void flash_wrapper_read_sig_area(uint8_t *sig, uint32_t ul_address, uint32_t len)
{
#ifdef TESTING
    (void) ul_address;
    memcpy(sig, flash_sig_area_simulation, len);
#else
    memcpy(sig, (uint8_t *)(ul_address), len);
#endif
}
