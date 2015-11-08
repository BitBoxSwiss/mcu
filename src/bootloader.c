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


#include <string.h>

#include "sam4s4a.h"
#include "conf_usb.h"
#include "mcu.h"
#include "ecc.h"
#include "sha2.h"
#include "flags.h"
#include "utils.h"
#include "touch.h"
#include "version.h"
#include "bootloader.h"


static char report[UDI_HID_REPORT_IN_SIZE]; // report to send
static uint8_t bootloader_loading_ready = 0;

static const char pubkey_c[] =
    "02a1137c6bdd497358537df77d1375a741ed75461b706a612a3717d32748e5acf1";


static void bootloader_report_status(BOOT_STATUS i)
{
    report[1] = i;
}


static void bootloader_write_page(const char *buf, uint8_t chunknum)
{
    bootloader_loading_ready = 0;

    if (FLASH_BOOT_OP_LEN + FLASH_BOOT_CHUNK_LEN != UDI_HID_REPORT_OUT_SIZE) {
        bootloader_report_status(OP_STATUS_ERR_MACRO);
        return;
    }

    if (chunknum > FLASH_BOOT_CHUNK_NUM) {
        bootloader_report_status(OP_STATUS_ERR_LEN);
        return;
    }

    if (!memcmp((uint32_t *)(FLASH_APP_START + (chunknum * FLASH_BOOT_CHUNK_LEN)), buf,
                FLASH_BOOT_CHUNK_LEN)) {
        bootloader_report_status(OP_STATUS_OK);
        bootloader_loading_ready = 1;
        return;
    }

    for (uint32_t i = 0; i < FLASH_BOOT_PAGES_PER_CHUNK; i++) {
        if (flash_write(FLASH_APP_START + (chunknum * FLASH_BOOT_CHUNK_LEN) +
                        (i * IFLASH0_PAGE_SIZE), buf + (i * IFLASH0_PAGE_SIZE), IFLASH0_PAGE_SIZE,
                        0) != FLASH_RC_OK) {
            bootloader_report_status(OP_STATUS_ERR_WRITE);
            return;
        }

        if (memcmp((uint32_t *)(FLASH_APP_START + (chunknum * FLASH_BOOT_CHUNK_LEN) +
                                (i * IFLASH0_PAGE_SIZE)), buf + (i * IFLASH0_PAGE_SIZE), IFLASH0_PAGE_SIZE)) {
            bootloader_report_status(OP_STATUS_ERR_CHECK);
            return;
        }
    }

    bootloader_report_status(OP_STATUS_OK);
    bootloader_loading_ready = 1;
}


static void bootloader_erase(void)
{
    bootloader_loading_ready = 0;

    if (touch_button_press(DBB_TOUCH_LONG) == DBB_TOUCHED) {
        flash_unlock(FLASH_APP_START, IFLASH0_ADDR + IFLASH0_SIZE, NULL, NULL);
        for (uint32_t i = 0; i < FLASH_APP_PAGE_NUM; i += 8) {
            if (flash_erase_page(FLASH_APP_START + IFLASH0_PAGE_SIZE * i,
                                 IFLASH_ERASE_PAGES_8) != FLASH_RC_OK) {
                bootloader_report_status(OP_STATUS_ERR_ERASE);
                return;
            }
        }
        bootloader_loading_ready = 1;
        bootloader_report_status(OP_STATUS_OK);
    } else {
        bootloader_report_status(OP_STATUS_ERR_ABORT);
    }
}


uint8_t bootloader_firmware_verified(void)
{
    uint8_t verified, hash[32], sig[FLASH_USER_SIG_SIZE];
    flash_read_user_signature((uint32_t *)sig, FLASH_USER_SIG_SIZE / sizeof(uint32_t));
    sha256_Raw((uint8_t *)(FLASH_APP_START), FLASH_APP_LEN, hash);
    verified = !ecc_verify(utils_hex_to_uint8(pubkey_c), sig, hash, 32); // hashed internally
    if (verified) {
        bootloader_report_status(OP_STATUS_OK);
    } else {
        bootloader_report_status(OP_STATUS_ERR);
    }
    sha256_Raw(hash, 32, hash);
    memcpy(report + 2, utils_uint8_to_hex(hash, 32), 64); // return double hash of app binary
    return verified;
}


uint8_t bootloader_unlocked(void)
{
    uint8_t sig[FLASH_USER_SIG_SIZE];
    flash_read_user_signature((uint32_t *)sig, FLASH_USER_SIG_SIZE / sizeof(uint32_t));
    return sig[FLASH_BOOT_LOCK_BYTE];
}


static char *bootloader(const char *command)
{
    memset(report, 0, sizeof(report));
    report[0] = command[0]; // OP_CODE

    switch (command[0]) {

        case OP_VERSION: {
            char *r = report;
            memcpy(r + 2, DIGITAL_BITBOX_VERSION, sizeof(DIGITAL_BITBOX_VERSION));
            break;
        }

        case OP_ERASE:
            bootloader_erase();
            break;

        case OP_WRITE:
            if (!bootloader_loading_ready) {
                bootloader_report_status(OP_STATUS_ERR_LOAD_FLAG);
            } else {
                bootloader_write_page(command + FLASH_BOOT_OP_LEN, command[1]);
            }
            break;

        case OP_VERIFY: {
            uint8_t sig[FLASH_USER_SIG_SIZE];
            memset(sig, 0xFF, FLASH_USER_SIG_SIZE);
            memcpy(sig, utils_hex_to_uint8(command + FLASH_BOOT_OP_LEN), 64);

            if (flash_erase_user_signature() != FLASH_RC_OK) {
                bootloader_report_status(OP_STATUS_ERR_ERASE);
                break;
            }

            if (flash_write_user_signature((uint32_t *)sig,
                                           FLASH_USER_SIG_SIZE / sizeof(uint32_t)) != FLASH_RC_OK) {
                bootloader_report_status(OP_STATUS_ERR_WRITE);
                break;
            }

            bootloader_firmware_verified();
            break;
        }

        default:
            bootloader_report_status(OP_STATUS_ERR_INVALID_CMD);
            bootloader_loading_ready = 0;
            break;
    }

    return report;
}


char *commander(const char *command)
{
    return bootloader(command);
}

