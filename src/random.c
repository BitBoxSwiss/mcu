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


#include <string.h>

#include "random.h"
#include "memory.h"
#include "flags.h"
#include "flash.h"
#ifndef TESTING
#include "ataes132.h"
#include "utils.h"
#include "sha2.h"
#include "mcu.h"


void random_init(void)
{
    /* pass */
}
#else
#include <time.h>
void random_init(void)
{
    srand(time(NULL));
}
#endif


uint32_t random_uint32(uint8_t update_seed)
{
    uint32_t rn32;
    uint8_t rn[4];
    if (random_bytes(rn, 4, update_seed) != DBB_ERROR) {
        memcpy(&rn32, rn, 4);
        return rn32;
    } else {
        return 0;
    }
}


int random_bytes(uint8_t *buf, uint32_t len, uint8_t update_seed)
{
#ifdef TESTING
    // Use standard libary for off chip RNG
    uint32_t i = 0;
    (void) update_seed;
    for (i = 0; i < len; i++) {
        buf[i] = rand();
    }
#else
    uint32_t i = 0, n = 0;
#ifndef BOOTLOADER
    uint8_t entropy[32], usersig[FLASH_USERSIG_SIZE] = {0};
    uint32_t serial[4] = {0};

    // Add entropy from second chip (MCU UID)
    flash_read_unique_id(serial, 4);
    sha256_Raw((uint8_t *)serial, sizeof(serial), entropy);
    for (i = 0; i < MAX(len, sizeof(serial)); i++) {
        buf[i % len] ^= entropy[i % MEM_PAGE_LEN];
    }
    // Add entropy from random bytes set during factory install
    sha256_Raw((uint8_t *)(FLASH_BOOT_START), FLASH_BOOT_LEN, entropy);
    sha256_Raw(entropy, sizeof(entropy), entropy);
    sha256_Raw(entropy, sizeof(entropy), entropy);
    for (i = 0; i < MAX(len, MEM_PAGE_LEN); i++) {
        buf[i % len] ^= entropy[i % MEM_PAGE_LEN];
    }
    // Add entropy from user (hashed device password)
    memcpy(entropy, memory_report_user_entropy(), sizeof(entropy));
    for (i = 0; i < MAX(len, MEM_PAGE_LEN); i++) {
        buf[i % len] ^= entropy[i % MEM_PAGE_LEN];
    }
    // Add entropy from usersig
    flash_read_user_signature((uint32_t *)usersig, FLASH_USERSIG_SIZE / sizeof(uint32_t));
    sha256_Raw(usersig, FLASH_USERSIG_SIZE, entropy);
    for (i = 0; i < MAX(len, MEM_PAGE_LEN); i++) {
        buf[i % len] ^= entropy[i % MEM_PAGE_LEN];
        usersig[i % FLASH_USERSIG_RN_LEN] = entropy[i % MEM_PAGE_LEN];
    }
#endif
    // Add entropy from ataes RNG
    const uint8_t ataes_cmd[] = {0x02, 0x02, 0x00, 0x00, 0x00, 0x00}; // Pseudo RNG
    const uint8_t ataes_cmd_up[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00}; // True RNG - writes to EEPROM
    uint8_t ret, ataes_ret[20] = {0}; // Random command return packet [Count(1) || Return Code (1) | Data(16) || CRC (2)]
    while (len > n) {
        if (update_seed) {
            ret = ataes_process(ataes_cmd_up, sizeof(ataes_cmd_up), ataes_ret, sizeof(ataes_ret));
            update_seed = 0;
        } else {
            ret = ataes_process(ataes_cmd, sizeof(ataes_cmd), ataes_ret, sizeof(ataes_ret));
        }
        if (ret == DBB_OK && ataes_ret[0] && !ataes_ret[1]) {
            for (i = 0; i < MIN(len - n, 16); i++) {
                buf[(n + i) % len] ^= ataes_ret[(2 + i) % sizeof(ataes_ret)];
            }
        } else {
            flash_erase_user_signature();
            flash_write_user_signature((uint32_t *)usersig, FLASH_USERSIG_SIZE / sizeof(uint32_t));
            HardFault_Handler();
            return DBB_ERROR;
        }
        n += 16;
    }
#endif
    return DBB_OK;
}
