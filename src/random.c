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
#ifndef TESTING
#include "ataes132.h"
#include "sha2.h"


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
    uint32_t i = 0;
#ifndef TESTING
    const uint8_t ataes_cmd[] = {0x02, 0x02, 0x00, 0x00, 0x00, 0x00}; // Pseudo RNG
    const uint8_t ataes_cmd_up[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00}; // True RNG - writes to EEPROM
    uint8_t ret, ataes_ret[20] = {0}; // Random command return packet [Count(1) || Return Code (1) | Data(16) || CRC (2)]

    while (len > i) {
        if (update_seed) {
            ret = ataes_process(ataes_cmd_up, sizeof(ataes_cmd_up), ataes_ret, sizeof(ataes_ret));
            update_seed = 0;
        } else {
            ret = ataes_process(ataes_cmd, sizeof(ataes_cmd), ataes_ret, sizeof(ataes_ret));
        }
        if (ret == DBB_OK && ataes_ret[0]) {
            memcpy(buf + i, ataes_ret + 2, (len - i) < 16 ? (len - i) : 16);
        } else {
            return DBB_ERROR;
        }
        i += 16;
    }
#ifndef BOOTLOADER
    // Add ataes independent entropy from random bytes set during factory install
    uint8_t entropy[32];
    sha256_Raw((uint8_t *)(FLASH_BOOT_START) + FLASH_BOOT_LEN / 2, FLASH_BOOT_LEN / 2,
               entropy);
    sha256_Raw(entropy, sizeof(entropy), entropy);
    for (i = 0; i < len; i++) {
        buf[i] ^= entropy[i % MEM_PAGE_LEN];
    }
    // Add ataes independent entropy from user
    memcpy(entropy, memory_report_aeskey(PASSWORD_STAND), sizeof(entropy));
    for (i = 0; i < len; i++) {
        buf[i] ^= entropy[i % MEM_PAGE_LEN];
    }
#endif
#else
    // Use standard libary for off chip RNG
    (void) update_seed;
    for (i = 0; i < len; i++) {
        buf[i] = rand();
    }
#endif
    return DBB_OK;
}
