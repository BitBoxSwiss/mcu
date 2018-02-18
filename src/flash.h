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


#ifndef _FLASH_H_
#define _FLASH_H_


#include <stdint.h>


// Flash: 256kB = 512 pages * 512B per page
// Memory map:
//  bootloader area  [  32kB; last 2kB reserved for factory installed entropy ]
//  firmware memory  [   4kB; contains firmaware signatures (7*64B), version (4B) and flags (1B); remaining RFU ]
//  firmware code    [ 220kB ]
#ifndef IFLASH0_ADDR
#define IFLASH0_ADDR                (0x00400000u)
#endif
#define FLASH_PAGE_SIZE             (IFLASH0_PAGE_SIZE)
#define FLASH_ERASE_SIZE            (FLASH_PAGE_SIZE * 8)// note: min flash erase size is 0x1000 (8 512-Byte pages)
#define FLASH_BOOT_START            (IFLASH0_ADDR)
#define FLASH_BOOT_LEN              (0x00008000u)
#define FLASH_BOOT_OP_LEN           (2)// 1 byte op code and 1 byte parameter
#define FLASH_BOOT_PAGES_PER_CHUNK  (8)
#define FLASH_BOOT_CHUNK_LEN        (IFLASH0_PAGE_SIZE * FLASH_BOOT_PAGES_PER_CHUNK)
#define FLASH_BOOT_CHUNK_NUM        (FLASH_APP_LEN / FLASH_BOOT_CHUNK_LEN)// app len should be a multiple of chunk len
#define FLASH_BOOT_LOCK_BYTE        (FLASH_SIG_LEN - 1)
#define FLASH_USERSIG_START         (0x00400000u)
#define FLASH_USERSIG_SIZE          (0x200u)
#define FLASH_USERSIG_RN_LEN        (0x20u)
#define FLASH_SIG_START             (IFLASH0_ADDR + FLASH_BOOT_LEN)
#define FLASH_SIG_LEN               (FLASH_ERASE_SIZE)
#define FLASH_APP_START             (IFLASH0_ADDR + FLASH_BOOT_LEN + FLASH_SIG_LEN)
#define FLASH_APP_LEN               (IFLASH0_SIZE - FLASH_BOOT_LEN - FLASH_SIG_LEN)
#define FLASH_APP_PAGE_NUM          (FLASH_APP_LEN / FLASH_PAGE_SIZE)
#define FLASH_APP_VERSION_LEN       (4)// 4 byte big endian unsigned int
#define FLASH_APP_VERSION_START     (FLASH_APP_START + FLASH_APP_LEN - FLASH_APP_VERSION_LEN)
#define FLASH_BOOT_LATEST_APP_VERSION_BYTES (FLASH_BOOT_LOCK_BYTE - FLASH_APP_VERSION_LEN)


#define MPU_REGION_VALID            (0x10)
#define MPU_REGION_ENABLE           (0x01)
#define MPU_REGION_NORMAL           (8 << 16)// TEX:0b001 S:0b0 C:0b0 B:0b0
#define MPU_REGION_STATE_NA         (0x00 << 24)// No access
#define MPU_REGION_STATE_PRIV_RW    (0x01 << 24)
#define MPU_REGION_STATE_RW         (0x03 << 24)
#define MPU_REGION_STATE_PRIV_RO    (0x05 << 24)
#define MPU_REGION_STATE_RO         (0x06 << 24)
#define MPU_REGION_STATE_XN         (0x01 << 28)


static inline uint32_t mpu_region_size(uint32_t size)
{
    uint32_t regionSize = 32;
    uint32_t ret = 4;

    while (ret < 31) {
        if (size <= regionSize) {
            break;
        } else {
            ret++;
        }
        regionSize <<= 1;
    }
    return (ret << 1);
}


#endif
