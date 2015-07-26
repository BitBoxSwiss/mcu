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
#include <stdio.h>
#include "sd.h"
#include "commander.h"
#include "flags.h"
#include "mcu.h"

uint32_t sd_update = 0;
uint32_t sd_fs_found = 0;
uint32_t sd_listing_pos = 0;
uint32_t sd_num_files = 0;

FATFS fs;


uint8_t sd_write(const char *f, uint16_t f_len, const char *t, uint16_t t_len)
{
    char file[256] = {0};
    memcpy(file, "0:", 2);
    memcpy(file + 2, f, (f_len < sizeof(file) - 2) ? f_len : sizeof(file) - 2);

    char text[512] = {0};
    if (t_len > sizeof(text) - 1) {
        commander_fill_report("sd_write", FLAG_ERR_SD_WRITE_LEN, ERROR);
        goto err;
    }

    sd_mmc_init();
    sd_listing_pos = 0;

    if (CTRL_FAIL == sd_mmc_test_unit_ready(0)) {
        commander_fill_report("sd_write", FLAG_ERR_SD_CARD, ERROR);
        goto err;
    }

    FRESULT res;
    FIL file_object;

    memset(&fs, 0, sizeof(FATFS));
    res = f_mount(LUN_ID_SD_MMC_0_MEM, &fs);
    if (FR_INVALID_DRIVE == res) {
        commander_fill_report("sd_write", FLAG_ERR_SD_MOUNT, ERROR);
        goto err;
    }

    file[0] = LUN_ID_SD_MMC_0_MEM + '0';
    res = f_open(&file_object, (char const *)file, FA_CREATE_NEW | FA_WRITE);
    if (res != FR_OK) {
        commander_fill_report("sd_write", FLAG_ERR_SD_FILE_EXISTS, ERROR);
        f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
        goto err;
    }

    memcpy(text, t, (t_len < sizeof(text) - 1) ? t_len : sizeof(text) - 1);
    if (0 == f_puts(text, &file_object)) {
        commander_fill_report("sd_write", FLAG_ERR_SD_WRITE, ERROR);
        f_close(&file_object);
        f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
        memset(text, 0, sizeof(text));
        goto err;
    }

    commander_fill_report("sd_write", "success", SUCCESS);

    f_close(&file_object);
    f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
    memset(text, 0, sizeof(text));
    memset(file, 0, sizeof(file));
    return SUCCESS;

err:
    memset(text, 0, sizeof(text));
    memset(file, 0, sizeof(file));
    return ERROR;
}


char *sd_load(const char *f, uint16_t f_len)
{
    char file[256] = {0};
    memcpy(file, "0:", 2);
    memcpy(file + 2, f, (f_len < sizeof(file) - 2) ? f_len : sizeof(file) - 2);

    static char text[512];
    memset(text, 0, sizeof(text));

    sd_mmc_init();
    sd_listing_pos = 0;

    if (CTRL_FAIL == sd_mmc_test_unit_ready(0)) {
        commander_fill_report("sd_load", FLAG_ERR_SD_CARD, ERROR);
        goto err;
    }

    FRESULT res;
    FIL file_object;
    memset(&fs, 0, sizeof(FATFS));
    res = f_mount(LUN_ID_SD_MMC_0_MEM, &fs);
    if (FR_INVALID_DRIVE == res) {
        commander_fill_report("sd_load", FLAG_ERR_SD_MOUNT, ERROR);
        goto err;
    }

    file[0] = LUN_ID_SD_MMC_0_MEM + '0';
    res = f_open(&file_object, (char const *)file, FA_OPEN_EXISTING | FA_READ);
    if (res != FR_OK) {
        commander_fill_report("sd_load", FLAG_ERR_SD_OPEN, ERROR);
        f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
        goto err;
    }

    if (0 == f_gets(text, sizeof(text), &file_object)) {
        commander_fill_report("sd_load", FLAG_ERR_SD_READ, ERROR);
        f_close(&file_object);
        f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
        goto err;
    }

    commander_fill_report("sd_load", "success", SUCCESS);

    f_close(&file_object);
    f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
    memset(file, 0, sizeof(file));
    return text;

err:
    memset(file, 0, sizeof(file));
    return NULL;
}


uint8_t sd_list(void)
{
    FILINFO fno;
    DIR dir;
    const char *path = "0:";
#if _USE_LFN
    char c_lfn[_MAX_LFN + 1];
    fno.lfname = c_lfn;
    fno.lfsize = sizeof(c_lfn);
#endif

    char files[1028] = {0};
    size_t f_len = 0;
    uint32_t pos = 1;


    sd_mmc_init();
    sd_listing_pos = 0;

    if (CTRL_FAIL == sd_mmc_test_unit_ready(0)) {
        commander_fill_report("sd_list", FLAG_ERR_SD_CARD, ERROR);
        goto err;
    }

    FRESULT res;
    memset(&fs, 0, sizeof(FATFS));
    res = f_mount(LUN_ID_SD_MMC_0_MEM, &fs);
    if (FR_INVALID_DRIVE == res) {
        commander_fill_report("sd_list", FLAG_ERR_SD_MOUNT, ERROR);
        goto err;
    }

    // Open the directory
    res = f_opendir(&dir, path);
    if (res == FR_OK) {
        for (;;) {
            char *pc_fn;
            res = f_readdir(&dir, &fno);
            if (res != FR_OK || fno.fname[0] == 0) {
                break;
            }

#if _USE_LFN
            pc_fn = *fno.lfname ? fno.lfname : fno.fname;
#else
            pc_fn = fno.fname;
#endif
            if (*pc_fn == '.') {
                continue;
            }

            f_len += strlen(pc_fn) + 2;
            if (f_len >= sizeof(files)) {
                f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
                commander_fill_report("sd_list", FLAG_ERR_NUM_FILES, ERROR);
                goto err;
            }

            if (pos >= sd_listing_pos) {
                strcat(files, pc_fn);
                strcat(files, ", ");
            }

            pos += 1;
        }
    }

    commander_fill_report("sd_list", files, SUCCESS);

    f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
    memset(files, 0, sizeof(files));
    return SUCCESS;

err:
    memset(files, 0, sizeof(files));
    return ERROR;

}


static uint8_t delete_files(char *path)
{
    int failed = 0;
    FRESULT res;
    FILINFO fno;
    DIR dir;
#if _USE_LFN
    static char lfn[_MAX_LFN + 1];
    fno.lfname = lfn;
    fno.lfsize = sizeof lfn;
#endif

    res = f_opendir(&dir, path);
    if (res == FR_OK) {
        for (;;) {

            char *pc_fn;
            res = f_readdir(&dir, &fno);
            if (res != FR_OK) {
                failed++;
                break;
            }

            if (fno.fname[0] == 0) { // no more files or directories
                break;
            }

#if _USE_LFN
            pc_fn = *fno.lfname ? fno.lfname : fno.fname;
#else
            pc_fn = fno.fname;
#endif
            if (*pc_fn == '.') {
                continue;
            }

            char f_object[1024];
            snprintf(f_object, sizeof(f_object), "%s/%s", path, pc_fn);

            if (fno.fattrib & AM_DIR) { // is a directory
                failed += delete_files(f_object);
            } else { // is a file
                FIL file;
                res = f_open(&file, (char const *)f_object, FA_OPEN_EXISTING | FA_WRITE);
                if (res != FR_OK) {
                    failed++;
                } else {
                    DWORD f_ps, fsize = file.fsize;
                    for (f_ps = 0; f_ps < fsize; f_ps++) {
                        f_putc(0xAC, &file); // overwrite data
                    }
                    if (f_close(&file) != FR_OK) {
                        failed++;
                    }
                }
            }
            if (f_unlink(f_object + 2) != FR_OK) {
                failed++;
            }
        }
    }
    return failed;
}


uint8_t sd_erase(void)
{
    int failed = 0;
    char p[] = "0:";
    char *path = p;

    sd_mmc_init();
    sd_listing_pos = 0;

    if (CTRL_FAIL == sd_mmc_test_unit_ready(0)) {
        commander_fill_report("sd_erase", FLAG_ERR_SD_CARD, ERROR);
        return ERROR;
    }

    FRESULT res;
    memset(&fs, 0, sizeof(FATFS));
    res = f_mount(LUN_ID_SD_MMC_0_MEM, &fs);
    if (FR_INVALID_DRIVE == res) {
        commander_fill_report("sd_erase", FLAG_ERR_SD_MOUNT, ERROR);
        return ERROR;
    }

    failed = delete_files(path);

    f_mount(LUN_ID_SD_MMC_0_MEM, NULL); // Unmount

    if (failed) {
        commander_fill_report("sd_erase", FLAG_ERR_SD_ERASE, ERROR);
        return ERROR;
    } else {
        commander_fill_report("sd_erase", "success", SUCCESS);
        return SUCCESS;
    }
}
