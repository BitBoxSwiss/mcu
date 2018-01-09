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
#include <stdint.h>

#include "sd.h"
#include "commander.h"
#include "flags.h"
#include "utils.h"


#ifdef TESTING
#include <dirent.h>


#define f_close         fclose
#define f_printf(a, b)  fprintf(a, "%s", b)
#define f_putc          fputc
#define f_gets          fgets
#define f_mount(...)    {}
#define f_mkdir(...)    {}
#define FRESULT         int
#define FO(a)           a
static char ROOTDIR[] = "tests/digitalbitbox";// If change, update tests/CMakeLists.txt

#else
#include <limits.h>
#include "mcu.h"


#define FO(a)           &a
uint32_t sd_update = 0;
uint32_t sd_fs_found = 0;
uint32_t sd_listing_pos = 0;
uint32_t sd_num_files = 0;
static char ROOTDIR[] = "0:/digitalbitbox";
FATFS fs;
#endif


uint8_t sd_write(const char *fn, const char *wallet_backup, const char *wallet_name,
                 uint8_t replace, int cmd)
{
    char file[256];
    char buffer[256];

    if (utils_limit_alphanumeric_hyphen_underscore_period(fn) != DBB_OK) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_BAD_CHAR);
        goto err;
    }

    memset(file, 0, sizeof(file));
    snprintf(file, sizeof(file), "%s/%s", ROOTDIR, fn);

#ifdef TESTING
    commander_fill_report(cmd_str(cmd), flag_msg(DBB_WARN_NO_MCU), DBB_OK);
    if (replace == DBB_SD_REPLACE) {
        if (sd_file_exists(fn) == DBB_OK) {
            commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_OPEN_FILE);
            goto err;
        }
    }
    FILE *file_object = fopen(file, "w");
#else

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

    res = f_open(FO(file_object), (char const *)file,
                 (replace == DBB_SD_REPLACE ? FA_CREATE_ALWAYS : FA_CREATE_NEW) | FA_WRITE);
    if (res != FR_OK) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_OPEN_FILE);
        f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
        goto err;
    }
#endif
    {
        int len_1, len_2, len_3, len_4, len_total, len_xref, stream_len;
        unsigned long n = 0;

        stream_len = strlens(wallet_backup) +
                     (strlens(wallet_backup) / (SD_PDF_LINE_BUF_SIZE / 2)) * strlens(SD_PDF_TEXT_CONT) +
                     strlens(SD_PDF_TEXT_0) +
                     strlens(SD_PDF_TEXT_1) +
                     strlens(SD_PDF_TEXT_2) +
                     strlens(wallet_name) * 2 +
                     (strlens(wallet_name) / (SD_PDF_LINE_BUF_SIZE / 2)) * strlens(SD_PDF_TEXT_CONT) +
                     strlens(SD_PDF_TEXT_3);

        len_1 = f_printf(FO(file_object), SD_PDF_HEAD);
        len_2 = f_printf(FO(file_object), SD_PDF_1_0);
        len_3 = f_printf(FO(file_object), SD_PDF_2_0);
        len_4 = f_printf(FO(file_object), SD_PDF_3_0);

        snprintf(buffer, sizeof(buffer), SD_PDF_4_0_HEAD, stream_len);
        len_xref = f_printf(FO(file_object), buffer);
        len_xref += f_printf(FO(file_object), SD_PDF_TEXT_0);
        while (n < strlens(wallet_backup)) {
            if (EOF == f_putc(wallet_backup[n], FO(file_object))) {
                commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_WRITE_FILE);
                f_close(FO(file_object));
                f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
                goto err;
            }
            if (++n % (SD_PDF_LINE_BUF_SIZE / 2) == 0) {
                len_xref += f_printf(FO(file_object), SD_PDF_TEXT_CONT);
            }
        }

        len_xref += n;
        len_xref += f_printf(FO(file_object), SD_PDF_TEXT_1);

        n = 0;
        while (n < strlens(wallet_name)) {
            if (EOF == f_putc(wallet_name[n], FO(file_object))) {
                commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_WRITE_FILE);
                f_close(FO(file_object));
                f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
                goto err;
            }
            if (++n % (SD_PDF_LINE_BUF_SIZE / 2) == 0) {
                len_xref += f_printf(FO(file_object), SD_PDF_TEXT_CONT);
            }
        }

        len_xref += n;
        len_xref += f_printf(FO(file_object), SD_PDF_TEXT_2);

        n = 0;
        while (n < strlens(wallet_name)) {
            if (EOF == f_putc(wallet_name[n], FO(file_object))) {
                commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_WRITE_FILE);
                f_close(FO(file_object));
                f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
                goto err;
            }
            if (++n % (SD_PDF_LINE_BUF_SIZE / 2) == 0) {
                len_xref += f_printf(FO(file_object), SD_PDF_TEXT_CONT);
            }
        }
        len_xref += n;
        len_xref += f_printf(FO(file_object), SD_PDF_TEXT_3);
        len_xref += f_printf(FO(file_object), SD_PDF_4_0_END);

        snprintf(buffer, sizeof(buffer), SD_PDF_END,
                 len_1,
                 len_1 + len_2,
                 len_1 + len_2 + len_3,
                 len_1 + len_2 + len_3 + len_4,
                 len_1 + len_2 + len_3 + len_4 + len_xref);
        len_total = f_printf(FO(file_object), buffer);

        if (len_1 == EOF || len_2 == EOF || len_3 == EOF || len_4 == EOF ||
                len_xref == EOF || len_total == EOF) {
            commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_WRITE_FILE);
            f_close(FO(file_object));
            f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
            goto err;
        }
    }

    f_close(FO(file_object));
    f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
    utils_zero(file, sizeof(file));
    return DBB_OK;
err:
    utils_zero(file, sizeof(file));
    return DBB_ERROR;
}


char *sd_load(const char *fn, int cmd)
{
    char file[256];
    static char text[512];

    if (utils_limit_alphanumeric_hyphen_underscore_period(fn) != DBB_OK) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_BAD_CHAR);
        goto err;
    }

    memset(file, 0, sizeof(file));
    memset(text, 0, sizeof(text));

    snprintf(file, sizeof(file), "%s/%s", ROOTDIR, fn);

#ifdef TESTING
    commander_fill_report(cmd_str(cmd), flag_msg(DBB_WARN_NO_MCU), DBB_OK);
    FILE *file_object = fopen(file, "r");
    if (!file_object) {
        goto err;
    }
#else

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

    res = f_open(FO(file_object), (char const *)file, FA_OPEN_EXISTING | FA_READ);
    if (res != FR_OK) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_OPEN_FILE);
        f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
        goto err;
    }
#endif
    char line[SD_PDF_LINE_BUF_SIZE];
    char *text_p = text;
    unsigned content_found = 0, text_p_index = 0;
    while (1) {
        if (0 == f_gets(line, sizeof(line), FO(file_object))) {
            commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_READ_FILE);
            f_close(FO(file_object));
            f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
            goto err;
        }

        if (strstr(line, SD_PDF_BACKUP_END)) {
            break;
        }

        if (content_found) {
            char *t0 = strchr(line, '(');
            char *t1 = strchr(line, ')');
            if (t0 && t1 && (t1 > t0) && (sizeof(text) > text_p_index)) {
                snprintf(text_p + text_p_index, sizeof(text) - text_p_index, "%s", t0 + 1);
                text_p_index += t1 - t0 - 1;
                text[text_p_index] = '\0';
            }
            continue;
        }

        if (strstr(line, SD_PDF_BACKUP_START)) {
            content_found = 1;
        }
    }

    f_close(FO(file_object));
    f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
    utils_zero(file, sizeof(file));
    return text;
err:
    utils_zero(file, sizeof(file));
    return NULL;
}


uint8_t sd_list(int cmd)
{
    char files[SD_FILEBUF_LEN_MAX] = {0};
    size_t f_len = 0;
    uint32_t pos = 1;

#ifdef TESTING
    commander_fill_report(cmd_str(cmd), flag_msg(DBB_WARN_NO_MCU), DBB_OK);
    uint32_t sd_listing_pos = 0;
    struct dirent *p_dirent;
    DIR *dir = opendir(ROOTDIR);
    if (dir) {
#else
    FILINFO fno;
    DIR dir;
#if _USE_LFN
    char c_lfn[_MAX_LFN + 1];
    fno.lfname = c_lfn;
    fno.lfsize = sizeof(c_lfn);
#endif

    sd_mmc_init();
    sd_listing_pos = 0;

    if (CTRL_FAIL == sd_mmc_test_unit_ready(0)) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_CARD);
        utils_zero(files, sizeof(files));
        return DBB_ERROR;
    }

    FRESULT res;
    memset(&fs, 0, sizeof(FATFS));
    res = f_mount(LUN_ID_SD_MMC_0_MEM, &fs);
    if (FR_INVALID_DRIVE == res) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_MOUNT);
        utils_zero(files, sizeof(files));
        return DBB_ERROR;
    }

    res = f_opendir(&dir, ROOTDIR);
    if (res == FR_OK) {
#endif
        strcat(files, "[");
        f_len++;
        for (;;) {
            char *pc_fn;
#ifdef TESTING
            p_dirent = readdir(dir);
            if (p_dirent == NULL) {
                break;
            }
            pc_fn = p_dirent->d_name;
#else
            res = f_readdir(&dir, &fno);
            if (res != FR_OK || fno.fname[0] == 0) {
                break;
            }
#if _USE_LFN
            pc_fn = *fno.lfname ? fno.lfname : fno.fname;
#else
            pc_fn = fno.fname;
#endif
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
                commander_fill_report(cmd_str(CMD_warning), flag_msg(DBB_WARN_SD_NUM_FILES), DBB_OK);
                strcat(files, "\"");
                break;
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
    utils_zero(files, sizeof(files));
#ifdef TESTING
    closedir(dir);
#endif
    return DBB_OK;
}


uint8_t sd_card_inserted(void)
{
#ifdef TESTING
    commander_fill_report(cmd_str(CMD_backup), flag_msg(DBB_WARN_NO_MCU), DBB_OK);
#else
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
#endif
    return DBB_OK;
}


uint8_t sd_file_exists(const char *fn)
{
    char file[256];
    memset(file, 0, sizeof(file));
    snprintf(file, sizeof(file), "%s/%s", ROOTDIR, fn);

#ifdef TESTING
    commander_fill_report(cmd_str(CMD_backup), flag_msg(DBB_WARN_NO_MCU), DBB_OK);
    FILE *file_object = fopen(file, "r");
    if (file_object) {
        f_close(FO(file_object));
        return DBB_OK;
    }
    return DBB_ERROR;
#else
    FIL file_object;
    FRESULT res;

    memset(file, 0, sizeof(file));
    snprintf(file, sizeof(file), "%s/%s", ROOTDIR, fn);

    sd_mmc_init();
    sd_listing_pos = 0;

    if (CTRL_FAIL == sd_mmc_test_unit_ready(0)) {
        utils_zero(file, sizeof(file));
        return DBB_ERR_SD_CARD;
    }

    memset(&fs, 0, sizeof(FATFS));
    res = f_mount(LUN_ID_SD_MMC_0_MEM, &fs);
    if (FR_INVALID_DRIVE == res) {
        utils_zero(file, sizeof(file));
        return DBB_ERR_SD_MOUNT;
    }

    res = f_open(FO(file_object), (char const *)file, FA_OPEN_EXISTING | FA_READ);
    if (res == FR_OK) {
        f_close(FO(file_object));
        f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
        utils_zero(file, sizeof(file));
        return DBB_OK;
    }
#endif
    f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
    utils_zero(file, sizeof(file));
    return DBB_ERROR;
}


static uint8_t sd_delete_files(char *path)
{
#ifdef TESTING
    (void) path;
    struct dirent *p_dirent;
    DIR *p_dir = opendir(ROOTDIR);
    char file[256];
    int ret = 0;
    if (p_dir) {
        while ((p_dirent = readdir(p_dir)) != NULL) {
            if (p_dirent->d_name[0] != '.') {
                snprintf(file, sizeof(file), "%s/%s", ROOTDIR, p_dirent->d_name);
                ret += remove(file);
            }
        }
        closedir(p_dir);
    }
    return ret;
#else
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
                failed += sd_delete_files(file);
            } else { // is a file
                FIL file_object;
                res = f_open(FO(file_object), (char const *)file, FA_OPEN_EXISTING | FA_WRITE);
                if (res != FR_OK) {
                    failed++;
                } else {
                    DWORD f_ps, fsize;
                    fsize = file_object.fsize < ULONG_MAX ? file_object.fsize : ULONG_MAX;
                    for (f_ps = 0; f_ps < fsize; f_ps++) {
                        f_putc(0xAC, FO(file_object)); // overwrite data
                    }
                    if (f_close(FO(file_object)) != FR_OK) {
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
#endif
}

static uint8_t sd_delete_file(const char *fn)
{
    char file[256];
    memset(file, 0, sizeof(file));
    snprintf(file, sizeof(file), "%s/%s", ROOTDIR, fn);
#ifdef TESTING
    return remove(file);
#else
    int failed = 0;
    FRESULT res;
    FIL file_object;

    res = f_open(FO(file_object), (char const *)file, FA_OPEN_EXISTING | FA_WRITE);
    if (res != FR_OK) {
        failed++;
    } else {
        DWORD f_ps, fsize;
        fsize = file_object.fsize < ULONG_MAX ? file_object.fsize : ULONG_MAX;
        for (f_ps = 0; f_ps < fsize; f_ps++) {
            f_putc(0xAC, FO(file_object)); // overwrite data
        }
        if (f_close(FO(file_object)) != FR_OK) {
            failed++;
        }
    }

    if (f_unlink(file + 2) != FR_OK) {
        failed++;
    }

    return failed;
#endif
}


uint8_t sd_erase(int cmd, const char *fn)
{
    int failed = 0;
    char *path = ROOTDIR;

#ifndef TESTING
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
#endif
    if (strlens(fn)) {
        if (utils_limit_alphanumeric_hyphen_underscore_period(fn) != DBB_OK) {
            commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_BAD_CHAR);
            f_mount(LUN_ID_SD_MMC_0_MEM, NULL); // Unmount
            return DBB_ERROR;
        }
        failed = sd_delete_file(fn);
    } else {
        failed = sd_delete_files(path);
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
