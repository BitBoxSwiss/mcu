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
#include "mcu.h"
#include "led.h"
#include "ecc.h"
#include "sha2.h"
#include "flags.h"
#include "utils.h"
#include "touch.h"
#include "version.h"
#include "bootloader.h"


static char report[UDI_HID_REPORT_IN_SIZE];
static uint8_t bootloader_loading_ready = 0;
static const char *pubkeys[] = { // order is important
    "02a1137c6bdd497358537df77d1375a741ed75461b706a612a3717d32748e5acf1",
    "0336f8d23499da107a84947e6d7246969bf1c82b7543908dd4d0ac4aa4f349b15d",
    "028f65d8bb45148082e93f1ad947828d51e387f8c72af35118016d55b2e69dd842",
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


static uint8_t bootloader_firmware_verified(void)
{
    uint8_t cnt = 0, valid = 0, hash[32], sig[64];
    const char **pubkey = pubkeys;

    sha256_Raw((uint8_t *)(FLASH_APP_START), FLASH_APP_LEN, hash);
    while (*pubkey && valid < BOOT_SIG_M) {
        memcpy(sig, (uint8_t *)(FLASH_SIG_START + cnt * sizeof(sig)), sizeof(sig));
        valid += !ecc_verify(utils_hex_to_uint8(*pubkey), sig, hash, 32); // hashed internally
        pubkey++;
        cnt++;
    }

    if (valid < BOOT_SIG_M) {
        bootloader_report_status(OP_STATUS_ERR);
    } else {
        bootloader_report_status(OP_STATUS_OK);
    }

    sha256_Raw(hash, 32, hash);
    memcpy(report + 2, utils_uint8_to_hex(hash, 32), 64); // return double hash of app binary
    return (valid < BOOT_SIG_M) ? 0 : 1;
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
            memset(sig, 0xFF, FLASH_SIG_LEN);
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


char *commander(const char *command)
{
    return bootloader(command);
}

