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


uint8_t sd_write(const char *fn, const char *backup, const char *xpub, uint8_t replace,
                 int cmd)
{
    char file[256];
    char buffer[256];

    if (utils_limit_alphanumeric_hyphen_underscore_period(fn) != DBB_OK) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_BAD_CHAR);
        goto err;
    }

    memset(file, 0, sizeof(file));
    snprintf(file, sizeof(file), "%s/%s", ROOTDIR, fn);

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

    {
        int len_1, len_2, len_3, len_4, len_total, len_xref, stream_len;
        unsigned long n = 0;

        stream_len = strlens(backup) +
                     (strlens(backup) / (SD_PDF_LINE_BUF_SIZE / 2)) * strlens(SD_PDF_TEXT_CONTINUE) +
                     strlens(SD_PDF_TEXT_START) +
                     strlens(SD_PDF_TEXT_END_1) +
                     strlens(xpub) +
                     (strlens(xpub) / (SD_PDF_LINE_BUF_SIZE / 2)) * strlens(SD_PDF_TEXT_CONTINUE) +
                     strlens(SD_PDF_TEXT_END_2);

        len_1 = f_printf(&file_object, SD_PDF_HEAD);
        len_2 = f_printf(&file_object, SD_PDF_1_0);
        len_3 = f_printf(&file_object, SD_PDF_2_0);
        len_4 = f_printf(&file_object, SD_PDF_3_0);

        snprintf(buffer, sizeof(buffer), SD_PDF_4_0_HEAD, stream_len);
        len_xref = f_printf(&file_object, buffer);
        len_xref += f_printf(&file_object, SD_PDF_TEXT_START);
        while (n < strlens(backup)) {
            if (EOF == f_putc(backup[n], &file_object)) {
                commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_WRITE_FILE);
                f_close(&file_object);
                f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
                goto err;
            }
            if (++n % (SD_PDF_LINE_BUF_SIZE / 2) == 0) {
                len_xref += f_printf(&file_object, SD_PDF_TEXT_CONTINUE);
            }
        }
        len_xref += n;
        len_xref += f_printf(&file_object, SD_PDF_TEXT_END_1);

        n = 0;
        while (n < strlens(xpub)) {
            if (EOF == f_putc(xpub[n], &file_object)) {
                commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_WRITE_FILE);
                f_close(&file_object);
                f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
                goto err;
            }
            if (++n % (SD_PDF_LINE_BUF_SIZE / 2) == 0) {
                len_xref += f_printf(&file_object, SD_PDF_TEXT_CONTINUE);
            }
        }
        len_xref += n;
        len_xref += f_printf(&file_object, SD_PDF_TEXT_END_2);
        len_xref += f_printf(&file_object, SD_PDF_4_0_END);

        snprintf(buffer, sizeof(buffer), SD_PDF_END,
                 len_1,
                 len_1 + len_2,
                 len_1 + len_2 + len_3,
                 len_1 + len_2 + len_3 + len_4,
                 len_1 + len_2 + len_3 + len_4 + len_xref);
        len_total = f_printf(&file_object, buffer);

        if (len_1 == EOF || len_2 == EOF || len_3 == EOF || len_4 == EOF ||
                len_xref == EOF || len_total == EOF) {
            commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_WRITE_FILE);
            f_close(&file_object);
            f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
            goto err;
        }
    }

    f_close(&file_object);
    f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
    memset(file, 0, sizeof(file));
    return DBB_OK;

err:
    memset(file, 0, sizeof(file));
    return DBB_ERROR;
}


char *sd_load(const char *fn, int cmd)
{
    FIL file_object;
    char file[256];
    static char text[512];

    if (utils_limit_alphanumeric_hyphen_underscore_period(fn) != DBB_OK) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_BAD_CHAR);
        goto err;
    }

    memset(file, 0, sizeof(file));
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

    snprintf(file, sizeof(file), "%s/%s", ROOTDIR, fn);
    res = f_open(&file_object, (char const *)file, FA_OPEN_EXISTING | FA_READ);
    if (res != FR_OK) {
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_OPEN_FILE);
        f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
        goto err;
    }

    char line[SD_PDF_LINE_BUF_SIZE];
    char *text_p = text;
    unsigned content_found = 0, text_p_index = 0;
    while (1) {
        if (0 == f_gets(line, sizeof(line), &file_object)) {
            commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_READ_FILE);
            f_close(&file_object);
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

    char files[SD_FILEBUF_LEN_MAX] = {0};
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
                commander_fill_report(cmd_str(CMD_warning), flag_msg(DBB_WARN_SD_NUM_FILES), DBB_OK);
                strcat(files, "\"]");
                goto exit;
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

exit:
    commander_fill_report(cmd_str(cmd), files, DBB_JSON_ARRAY);

    f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
    memset(files, 0, sizeof(files));
    return DBB_OK;

err:
    memset(files, 0, sizeof(files));
    return DBB_ERROR;

}


uint8_t sd_card_inserted(void)
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


uint8_t sd_file_exists(const char *fn)
{
    FIL file_object;
    char file[256];

    memset(file, 0, sizeof(file));
    snprintf(file, sizeof(file), "%s/%s", ROOTDIR, fn);

    sd_mmc_init();
    sd_listing_pos = 0;

    if (CTRL_FAIL == sd_mmc_test_unit_ready(0)) {
        memset(file, 0, sizeof(file));
        return DBB_ERR_SD_CARD;
    }

    FRESULT res;
    memset(&fs, 0, sizeof(FATFS));
    res = f_mount(LUN_ID_SD_MMC_0_MEM, &fs);
    if (FR_INVALID_DRIVE == res) {
        memset(file, 0, sizeof(file));
        return DBB_ERR_SD_MOUNT;
    }

    res = f_open(&file_object, (char const *)file, FA_OPEN_EXISTING | FA_READ);
    if (res == FR_OK) {
        f_close(&file_object);
        f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
        memset(file, 0, sizeof(file));
        return DBB_OK;
    }

    f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
    memset(file, 0, sizeof(file));
    return DBB_ERROR;
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
        if (utils_limit_alphanumeric_hyphen_underscore_period(fn) != DBB_OK) {
            commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_SD_BAD_CHAR);
            f_mount(LUN_ID_SD_MMC_0_MEM, NULL); // Unmount
            return DBB_ERROR;
        }
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
