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
#include <stdio.h>
#include <limits.h>

#include "sd.h"
#include "commander.h"
#include "flags.h"
#include "utils.h"
#include "mcu.h"


uint32_t sd_update = 0;
uint32_t sd_fs_found = 0;
uint32_t sd_listing_pos = 0;
uint32_t sd_num_files = 0;

static char ROOTDIR[] = "0:/digitalbitbox";

FATFS fs;


uint8_t sd_write(const char *fn, const char *t, uint16_t t_len,
                 uint8_t replace, int cmd)
{
    char file[256];
    memset(file, 0, sizeof(file));
    snprintf(file, sizeof(file), "%s/%s", ROOTDIR, fn);

    char text[512] = {0};
    if (t_len > sizeof(text) - 1) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_WRITE_LEN);
        goto err;
    }

    sd_mmc_init();
    sd_listing_pos = 0;

    if (CTRL_FAIL == sd_mmc_test_unit_ready(0)) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_CARD);
        goto err;
    }

    FRESULT res;
    FIL file_object;

    memset(&fs, 0, sizeof(FATFS));
    res = f_mount(LUN_ID_SD_MMC_0_MEM, &fs);
    if (FR_INVALID_DRIVE == res) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_MOUNT);
        goto err;
    }

    f_mkdir(ROOTDIR);

    res = f_open(&file_object, (char const *)file,
                 (replace == DBB_SD_REPLACE ? FA_CREATE_ALWAYS : FA_CREATE_NEW) | FA_WRITE);
    if (res != FR_OK) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_OPEN_FILE);
        f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
        goto err;
    }

    snprintf(text, sizeof(text) - 1, "%.*s", t_len, t);
    if (0 == f_puts(text, &file_object)) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_WRITE_FILE);
        f_close(&file_object);
        f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
        memset(text, 0, sizeof(text));
        goto err;
    }

    f_close(&file_object);
    f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
    memset(text, 0, sizeof(text));
    memset(file, 0, sizeof(file));
    return DBB_OK;

err:
    memset(text, 0, sizeof(text));
    memset(file, 0, sizeof(file));
    return DBB_ERROR;
}


char *sd_load(const char *fn, int cmd)
{
    FIL file_object;
    char file[256];
    memset(file, 0, sizeof(file));
    snprintf(file, sizeof(file), "%s/%s", ROOTDIR, fn);


    static char text[512];
    memset(text, 0, sizeof(text));

    sd_mmc_init();
    sd_listing_pos = 0;

    if (CTRL_FAIL == sd_mmc_test_unit_ready(0)) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_CARD);
        goto err;
    }

    FRESULT res;
    memset(&fs, 0, sizeof(FATFS));
    res = f_mount(LUN_ID_SD_MMC_0_MEM, &fs);
    if (FR_INVALID_DRIVE == res) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_MOUNT);
        goto err;
    }

    res = f_open(&file_object, (char const *)file, FA_OPEN_EXISTING | FA_READ);
    if (res != FR_OK) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_OPEN_FILE);
        f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
        goto err;
    }

    UINT text_read;
    res = f_read(&file_object, text, file_object.fsize, &text_read);
    if (res != FR_OK) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_READ_FILE);
        f_close(&file_object);
        f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
        goto err;
    }

    f_close(&file_object);
    f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
    memset(file, 0, sizeof(file));
    return text;

err:
    memset(file, 0, sizeof(file));
    return NULL;
}


uint8_t sd_list(int cmd)
{
    FILINFO fno;
    DIR dir;
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
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_CARD);
        goto err;
    }

    FRESULT res;
    memset(&fs, 0, sizeof(FATFS));
    res = f_mount(LUN_ID_SD_MMC_0_MEM, &fs);
    if (FR_INVALID_DRIVE == res) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_MOUNT);
        goto err;
    }

    // Open the directory
    res = f_opendir(&dir, ROOTDIR);
    if (res == FR_OK) {
        strcat(files, "[");
        f_len++;
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
            if (*pc_fn == '.' && *(pc_fn + 1) == '\0') {
                continue;
            }
            if (*pc_fn == '.' && *(pc_fn + 1) == '.' && *(pc_fn + 2) == '\0') {
                continue;
            }

            f_len += strlen(pc_fn) + strlens(",\"\"");
            if (f_len + 1 >= sizeof(files)) {
                f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
                commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_NUM_FILES);
                goto err;
            }

            if (pos >= sd_listing_pos) {
                if (strlens(files) > 1) {
                    strcat(files, ",");
                }
                snprintf(files + strlens(files), sizeof(files) - f_len, "\"%s\"", pc_fn);
            }

            pos += 1;
        }
        strcat(files, "]");
    } else {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_OPEN_DIR);
    }

    commander_fill_report(cmd_str(cmd), files, DBB_JSON_ARRAY);

    f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
    memset(files, 0, sizeof(files));
    return DBB_OK;

err:
    memset(files, 0, sizeof(files));
    return DBB_ERROR;

}


uint8_t sd_present(void)
{
    sd_mmc_init();
    sd_listing_pos = 0;

    if (CTRL_FAIL == sd_mmc_test_unit_ready(0)) {
        return DBB_ERROR;
    }

    memset(&fs, 0, sizeof(FATFS));
    if (FR_INVALID_DRIVE == f_mount(LUN_ID_SD_MMC_0_MEM, &fs)) {
        return DBB_ERROR;
    }
    f_mount(LUN_ID_SD_MMC_0_MEM, NULL);

    return DBB_OK;
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
            if (*pc_fn == '.' && *(pc_fn + 1) == '\0') {
                continue;
            }
            if (*pc_fn == '.' && *(pc_fn + 1) == '.' && *(pc_fn + 2) == '\0') {
                continue;
            }

            char file[1024];
            snprintf(file, sizeof(file), "%s/%s", path, pc_fn);

            if (fno.fattrib & AM_DIR) { // is a directory
                failed += delete_files(file);
            } else { // is a file
                FIL file_object;
                res = f_open(&file_object, (char const *)file, FA_OPEN_EXISTING | FA_WRITE);
                if (res != FR_OK) {
                    failed++;
                } else {
                    DWORD f_ps, fsize;
                    fsize = file_object.fsize < ULONG_MAX ? file_object.fsize : ULONG_MAX;
                    for (f_ps = 0; f_ps < fsize; f_ps++) {
                        f_putc(0xAC, &file_object); // overwrite data
                    }
                    if (f_close(&file_object) != FR_OK) {
                        failed++;
                    }
                }
            }
            if (f_unlink(file + 2) != FR_OK) {
                failed++;
            }
        }
    }
    return failed;
}


static uint8_t delete_file(const char *fn)
{
    int failed = 0;
    FRESULT res;
    FIL file_object;
    char file[256];
    memset(file, 0, sizeof(file));
    snprintf(file, sizeof(file), "%s/%s", ROOTDIR, fn);

    res = f_open(&file_object, (char const *)file, FA_OPEN_EXISTING | FA_WRITE);
    if (res != FR_OK) {
        failed++;
    } else {
        DWORD f_ps, fsize;
        fsize = file_object.fsize < ULONG_MAX ? file_object.fsize : ULONG_MAX;
        for (f_ps = 0; f_ps < fsize; f_ps++) {
            f_putc(0xAC, &file_object); // overwrite data
        }
        if (f_close(&file_object) != FR_OK) {
            failed++;
        }
    }

    if (f_unlink(file + 2) != FR_OK) {
        failed++;
    }

    return failed;
}


uint8_t sd_erase(int cmd, const char *fn)
{
    int failed = 0;
    char *path = ROOTDIR;

    sd_mmc_init();
    sd_listing_pos = 0;

    if (CTRL_FAIL == sd_mmc_test_unit_ready(0)) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_CARD);
        return DBB_ERROR;
    }

    FRESULT res;
    memset(&fs, 0, sizeof(FATFS));
    res = f_mount(LUN_ID_SD_MMC_0_MEM, &fs);
    if (FR_INVALID_DRIVE == res) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_MOUNT);
        return DBB_ERROR;
    }

    if (strlens(fn)) {
        failed = delete_file(fn);
    } else {
        failed = delete_files(path);
    }

    f_mount(LUN_ID_SD_MMC_0_MEM, NULL); // Unmount

    if (failed) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_ERASE);
        return DBB_ERROR;
    } else {
        commander_fill_report(cmd_str(cmd), attr_str(ATTR_success), DBB_OK);
        return DBB_OK;
    }
}
