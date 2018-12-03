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


#include <string.h>

#include "sam4s4a.h"
#include "conf_usb.h"
#include "drivers/config/mcu.h"
#include "led.h"
#include "uECC.h"
#include "sha2.h"
#include "flags.h"
#include "flash.h"
#include "utils.h"
#include "touch.h"
#include "version.h"
#include "bootloader.h"
#include "mpu.h"


static char report[UDI_HID_REPORT_IN_SIZE];
static uint8_t bootloader_loading_ready = 0;
static const char *pubkeys[] = { // order is important
    "02a1137c6bdd497358537df77d1375a741ed75461b706a612a3717d32748e5acf1",
    "0256201125b958864de4bb00560a247ad246182866b6fe7ac29d7a12e7718ebb7d",
    "03d2185d70fb29a36691d8470e65d02adfab2ec00caad91887da23e5ad20a25163",
    "0263b742d9873405c609814da884324ab0f4c1597a5fd152b388899857f4d041df",
    "02b95dc22d293376222ef896f74a8436a8b6672e7e416299f3c4e23b49c38ad366",
    "03ef4c48dc308ace971c025db3edd4bc5d5110e28e14bdd925fffafd4d21002800",
    "030d8b0b86fca70bfd3a8d842cdb3ff8362c02f455fd092b080f1bb137dfc1d25f",
    0
};


void _binExec (void *l_code_addr);
void _binExec (void *l_code_addr)
{
    __asm__ (
        "mov   r1, r0        \n"
        "ldr   r0, [r1, #4]  \n"
        "ldr   sp, [r1]      \n"
        "blx   r0"
    );
    (void)l_code_addr;
}


static int binary_exec(void *vStart)
{
    int i;

    // Should be at least 32 words aligned
    if ((uint32_t)vStart & 0x7F) {
        return 1;
    }

    __disable_irq();
    for (i = 0; i < 8; i ++) {
        NVIC->ICER[i] = 0xFFFFFFFF;
    }
    for (i = 0; i < 8; i ++) {
        NVIC->ICPR[i] = 0xFFFFFFFF;
    }
    __DSB();
    __ISB();
    SCB->VTOR = ((uint32_t)vStart & SCB_VTOR_TBLOFF_Msk);
    __DSB();
    __ISB();
    __enable_irq();
    _binExec(vStart);

    return 0;
}


static void bootloader_report_status(BOOT_STATUS i)
{
    report[1] = i;
}


static void bootloader_write_chunk(const char *buf, uint8_t chunknum)
{
    bootloader_loading_ready = 0;

    if (FLASH_BOOT_OP_LEN + FLASH_BOOT_CHUNK_LEN != UDI_HID_REPORT_OUT_SIZE) {
        bootloader_report_status(OP_STATUS_ERR_MACRO);
        return;
    }

    if (chunknum > FLASH_BOOT_CHUNK_NUM - 1) {
        bootloader_report_status(OP_STATUS_ERR_LEN);
        return;
    }

    if (MEMEQ((uint32_t *)(FLASH_APP_START + (chunknum * FLASH_BOOT_CHUNK_LEN)), buf,
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

        if (!MEMEQ((uint32_t *)(FLASH_APP_START + (chunknum * FLASH_BOOT_CHUNK_LEN) +
                                (i * IFLASH0_PAGE_SIZE)), buf + (i * IFLASH0_PAGE_SIZE), IFLASH0_PAGE_SIZE)) {
            bootloader_report_status(OP_STATUS_ERR_CHECK);
            return;
        }
    }

    bootloader_report_status(OP_STATUS_OK);
    bootloader_loading_ready = 1;
}


static void bootloader_firmware_erase(void)
{
    bootloader_loading_ready = 0;
    flash_unlock(FLASH_APP_START, FLASH_APP_START + FLASH_APP_LEN, NULL, NULL);
    for (uint32_t i = 0; i < FLASH_APP_PAGE_NUM; i += 8) {
        if (flash_erase_page(FLASH_APP_START + IFLASH0_PAGE_SIZE * i,
                             IFLASH_ERASE_PAGES_8) != FLASH_RC_OK) {
            bootloader_report_status(OP_STATUS_ERR_ERASE);
            return;
        }
    }
    bootloader_loading_ready = 1;
    bootloader_report_status(OP_STATUS_OK);
}

static inline uint32_t bootloader_parse_app_version(uint8_t *start)
{
    uint32_t version = (*start << 24) | (*(start + 1) << 16) | (*(start + 2) << 8) | (*
                       (start + 3));
    if (version == 0xffffffff) {
        version = 0;
    }
    return version;
}

static uint8_t bootloader_firmware_verified(void)
{
    uint8_t cnt = 0, valid = 0, hash[32], sig[64], pubkey_64[64];
    const char **pubkey = pubkeys;

    sha256_Raw((uint8_t *)(FLASH_APP_START), FLASH_APP_LEN, hash);
    sha256_Raw(hash, 32, hash);

    while (*pubkey && valid < BOOT_SIG_M) {
        memcpy(sig, (uint8_t *)(FLASH_SIG_START + cnt * sizeof(sig)), sizeof(sig));
        uECC_decompress(utils_hex_to_uint8(*pubkey), pubkey_64, uECC_secp256k1());
        valid += uECC_verify(pubkey_64, hash, SHA256_DIGEST_LENGTH, sig,
                             uECC_secp256k1());
        pubkey++;
        cnt++;
    }
    memcpy(report + 2, utils_uint8_to_hex(hash, 32), 64); // return double hash of app binary

    if (valid < BOOT_SIG_M) {
        bootloader_report_status(OP_STATUS_ERR);
        return 0;
    }

    uint32_t app_version = bootloader_parse_app_version((uint8_t *)FLASH_APP_VERSION_START);
    uint32_t app_latest_version = bootloader_parse_app_version((uint8_t *)(
                                      FLASH_SIG_START + FLASH_BOOT_LATEST_APP_VERSION_BYTES));
    memcpy(report + 2 + 64, utils_uint8_to_hex((uint8_t *)(FLASH_SIG_START +
            FLASH_BOOT_LATEST_APP_VERSION_BYTES), FLASH_APP_VERSION_LEN), 2 * FLASH_APP_VERSION_LEN);
    memcpy(report + 2 + 64 + 2 * FLASH_APP_VERSION_LEN,
           utils_uint8_to_hex((uint8_t *)FLASH_APP_VERSION_START, FLASH_APP_VERSION_LEN),
           2 * FLASH_APP_VERSION_LEN);
    if (app_version < app_latest_version) {
        bootloader_report_status(OP_STATUS_ERR_VERSION);
        return 0;
    }

    bootloader_report_status(OP_STATUS_OK);
    return 1;
}


static uint8_t bootloader_unlocked(void)
{
    uint8_t sig[FLASH_SIG_LEN];
    memcpy(sig, (uint8_t *)(FLASH_SIG_START), FLASH_SIG_LEN);
    return sig[FLASH_BOOT_LOCK_BYTE];
}


static void bootloader_blink(void)
{
    led_toggle();
    delay_ms(300);
    led_toggle();
    bootloader_report_status(OP_STATUS_OK);
}


static void bootloader_reboot(void)
{
    NVIC_SystemReset();
}

void bootloader_command(const char *command)
{
    memset(report, 0, sizeof(report));
    report[0] = command[0]; // OP_CODE

    switch (command[0]) {

        case OP_LOCK: {
            if (bootloader_firmware_verified()) {
                uint8_t sig[FLASH_SIG_LEN];
                memcpy(sig, (uint8_t *)FLASH_SIG_START, FLASH_SIG_LEN);
                sig[FLASH_BOOT_LOCK_BYTE] = 0;

                flash_unlock(FLASH_SIG_START, FLASH_SIG_START + FLASH_SIG_LEN, NULL, NULL);
                if (flash_erase_page(FLASH_SIG_START, IFLASH_ERASE_PAGES_8) != FLASH_RC_OK) {
                    bootloader_report_status(OP_STATUS_ERR_ERASE);
                    break;
                }

                if (flash_write(FLASH_SIG_START, sig, FLASH_SIG_LEN, 0) != FLASH_RC_OK) {
                    bootloader_report_status(OP_STATUS_ERR_WRITE);
                    break;
                }
            }
            break;
        }

        case OP_VERSION: {
            char *r = report;
            memcpy(r + 2, DIGITAL_BITBOX_VERSION, sizeof(DIGITAL_BITBOX_VERSION));
            break;
        }

        case OP_ERASE:
            bootloader_firmware_erase();
            break;

        case OP_BLINK:
            bootloader_blink();
            break;

        case OP_REBOOT:
            bootloader_reboot();
            break;

        case OP_WRITE:
            if (!bootloader_loading_ready) {
                bootloader_report_status(OP_STATUS_ERR_LOAD_FLAG);
            } else {
                bootloader_write_chunk(command + FLASH_BOOT_OP_LEN, command[1]);
            }
            break;

        case OP_VERIFY: {
            uint8_t sig[FLASH_SIG_LEN];
            uint8_t cnt = 0;
            const char **pubkey = pubkeys;
            while (*pubkey) {
                pubkey++;
                cnt++;
            }
            memcpy(sig, (uint8_t *)FLASH_SIG_START, FLASH_SIG_LEN);
            memcpy(sig, utils_hex_to_uint8(command + FLASH_BOOT_OP_LEN), cnt * 64);

            flash_unlock(FLASH_SIG_START, FLASH_SIG_START + FLASH_SIG_LEN, NULL, NULL);
            if (flash_erase_page(FLASH_SIG_START, IFLASH_ERASE_PAGES_8) != FLASH_RC_OK) {
                bootloader_report_status(OP_STATUS_ERR_ERASE);
                break;
            }

            if (flash_write(FLASH_SIG_START, sig, FLASH_SIG_LEN, 0) != FLASH_RC_OK) {
                bootloader_report_status(OP_STATUS_ERR_WRITE);
                break;
            }

            if (bootloader_firmware_verified()) {

                memcpy((uint8_t *)sig + FLASH_BOOT_LATEST_APP_VERSION_BYTES,
                       (uint8_t *)FLASH_APP_VERSION_START,
                       FLASH_APP_VERSION_LEN);

                if (flash_erase_page(FLASH_SIG_START, IFLASH_ERASE_PAGES_8) != FLASH_RC_OK) {
                    bootloader_report_status(OP_STATUS_ERR_ERASE);
                    break;
                }

                if (flash_write(FLASH_SIG_START, sig, FLASH_SIG_LEN, 0) != FLASH_RC_OK) {
                    bootloader_report_status(OP_STATUS_ERR_WRITE);
                    break;
                }
            }

            break;
        }
        default:
            bootloader_report_status(OP_STATUS_ERR_INVALID_CMD);
            bootloader_loading_ready = 0;
            break;
    }

    usb_reply((uint8_t *)report);
}

void bootloader_jump(void)
{
    void *app_start_addr = (void *)FLASH_APP_START;

    if (bootloader_firmware_verified()) {
        if (!bootloader_unlocked()) {
            binary_exec(app_start_addr);
            /* no return */
        }
        if (touch_button_press(DBB_TOUCH_TIMEOUT) == DBB_ERR_TOUCH_TIMEOUT) {
            binary_exec(app_start_addr);
            /* no return */
        }
    } else {
        for (int i = 0; i < 9; i++) {
            led_toggle();
            delay_ms(100);
            led_toggle();
            delay_ms(150);
        }
        led_off();
    }

    // App not entered. Start USB API to receive boot commands
    usb_suspend_action();
    udc_start();

    for (int i = 0; i < 6; i++) {
        led_toggle();
        delay_ms(100);
    }
    led_off();
}
