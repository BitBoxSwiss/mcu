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
#include <stdlib.h>
#include <stdio.h>

#include "yajl/src/api/yajl_tree.h"
#include "commander.h"
#include "version.h"
#include "random.h"
#include "base64.h"
#include "wallet.h"
#include "touch.h"
#include "utils.h"
#include "flash.h"
#include "flags.h"
#include "sha2.h"
#include "aes.h"
#include "cipher.h"
#include "hmac.h"
#include "led.h"
#include "ecc.h"
#include "sd.h"
#include "drivers/config/mcu.h"
#include "ecdh.h"


#if defined(TESTING) && defined(__SAM4S4A__)
#error TESTING should not be defined for embedded code
#endif


#define BRACED(x) (strlens(x) ? (((x[0]) == '{') && ((x[strlens(x) - 1]) == '}')) : 0)


extern const uint8_t MEM_PAGE_ERASE[MEM_PAGE_LEN];
extern const uint8_t MEM_PAGE_ERASE_FE[MEM_PAGE_LEN];

static int REPORT_BUF_OVERFLOW = 0;
__extension__ static char json_array[] = {[0 ... COMMANDER_ARRAY_MAX] = 0};
__extension__ static char json_report[] = {[0 ... COMMANDER_REPORT_SIZE] = 0};
__extension__ static char sign_command[] = {[0 ... COMMANDER_REPORT_SIZE] = 0};
static char TFA_PIN[TFA_PIN_LEN * 2 + 1];
static int TFA_VERIFY = 0;


//
//  Reporting results  //
//

void commander_clear_report(void)
{
    memset(json_report, 0, COMMANDER_REPORT_SIZE);
    REPORT_BUF_OVERFLOW = 0;
}


const char *commander_read_report(void)
{
    return json_report;
}


void commander_fill_report(const char *cmd, const char *msg, int flag)
{
    char *p = json_report;

    if (!strlens(json_report)) {
        strncat(json_report, "{", 1);
    } else {
        json_report[strlens(json_report) - 1] = ','; // replace closing '}' with continuing ','
    }

    if (flag > DBB_FLAG_ERROR_START) {
        if (strlens(msg)) {
            snprintf(p + strlens(json_report), COMMANDER_REPORT_SIZE - strlens(json_report),
                     "\"%s\":{\"message\":\"%s\",\"code\":%s,\"command\":\"%s\"}",
                     attr_str(ATTR_error), msg, flag_code(flag), cmd);
        } else {
            snprintf(p + strlens(json_report), COMMANDER_REPORT_SIZE - strlens(json_report),
                     "\"%s\":{\"message\":\"%s\",\"code\":%s,\"command\":\"%s\"}",
                     attr_str(ATTR_error), flag_msg(flag), flag_code(flag), cmd);
        }
    } else if (flag == DBB_JSON_BOOL || flag == DBB_JSON_ARRAY || flag == DBB_JSON_NUMBER ||
               flag == DBB_JSON_OBJECT) {
        snprintf(p + strlens(json_report), COMMANDER_REPORT_SIZE - strlens(json_report),
                 "\"%s\":%s", cmd, msg);
    } else {
        snprintf(p + strlens(json_report), COMMANDER_REPORT_SIZE - strlens(json_report),
                 "\"%s\":\"%s\"", cmd, msg);
    }

    if ((strlens(json_report) + 1) >= COMMANDER_REPORT_SIZE) {
        if (!REPORT_BUF_OVERFLOW) {
            commander_clear_report();
            snprintf(json_report, COMMANDER_REPORT_SIZE,
                     "{\"%s\":{\"message\":\"%s\",\"code\":%s,\"command\":\"%s\"}}", attr_str(ATTR_error),
                     flag_msg(DBB_ERR_IO_REPORT_BUF), flag_code(DBB_ERR_IO_REPORT_BUF), cmd);
            REPORT_BUF_OVERFLOW = 1;
        }
    } else {
        strcat(json_report, "}");
    }
}


int commander_fill_json_array(const char **key, const char **value, int *type, int cmd)
{
    int i = 0;
    char array_element[COMMANDER_ARRAY_ELEMENT_MAX];
    char *p = array_element;
    memset(array_element, 0, COMMANDER_ARRAY_ELEMENT_MAX);

    // create array element
    strcat(array_element, "{");
    while (*key && *value && !REPORT_BUF_OVERFLOW) {
        if (i++ > 0) {
            strcat(array_element, ",");
        }
        if (type[i - 1] == DBB_JSON_STRING) {
            snprintf(p + strlens(array_element),
                     COMMANDER_ARRAY_ELEMENT_MAX - strlens(array_element), " \"%s\":\"%s\"", *key, *value);
        } else {
            snprintf(p + strlens(array_element),
                     COMMANDER_ARRAY_ELEMENT_MAX - strlens(array_element), " \"%s\":%s", *key, *value);
        }
        if ((strlens(array_element) + 1) >= COMMANDER_ARRAY_ELEMENT_MAX) {
            commander_clear_report();
            commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_IO_REPORT_BUF);
            REPORT_BUF_OVERFLOW = 1;
            return DBB_ERROR;
        }
        key++;
        value++;
    }
    strcat(array_element, "}");

    // add element to array
    if (!strlens(json_array)) {
        strncat(json_array, "[", 1);
    } else {
        json_array[strlens(json_array) - 1] = ','; // replace closing ']' with continuing ','
    }

    p = json_array;

    snprintf(p + strlens(json_array), COMMANDER_ARRAY_MAX - strlens(json_array), "%s",
             array_element);

    if ((strlens(json_array) + 1) >= COMMANDER_ARRAY_MAX) {
        commander_clear_report();
        commander_fill_report(cmd_str(cmd), NULL, DBB_ERR_IO_REPORT_BUF);
        REPORT_BUF_OVERFLOW = 1;
        return DBB_ERROR;
    } else {
        strcat(json_array, "]");
        return DBB_OK;
    }
}


const char *commander_read_array(void)
{
    return json_array;
}


int commander_fill_signature_array(const uint8_t sig[64], uint8_t recid)
{
    char recid_c[2 + 1] = {0};
    char sig_c[128 + 1] = {0};
    snprintf(recid_c, sizeof(recid_c), "%02x", recid);
    snprintf(sig_c, sizeof(sig_c), "%s", utils_uint8_to_hex(sig, 64));
    const char *key[] = {cmd_str(CMD_sig), cmd_str(CMD_recid), 0};
    const char *value[] = {sig_c, recid_c, 0};
    int type[] = {DBB_JSON_STRING, DBB_JSON_STRING, DBB_JSON_STRING, DBB_JSON_NONE};
    return commander_fill_json_array(key, value, type, CMD_sign);
}


//
//  Command processing  //
//

void commander_force_reset(void)
{
    memory_reset_hww();
    commander_clear_report();
    commander_fill_report(cmd_str(CMD_reset), NULL, DBB_ERR_IO_RESET);
}


static void commander_process_reset(yajl_val json_node)
{
    const char *path[] = { cmd_str(CMD_reset), NULL };
    const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));

    if (!strlens(value)) {
        commander_fill_report(cmd_str(CMD_reset), NULL, DBB_ERR_IO_INVALID_CMD);
        return;
    }

    if (STREQ(value, attr_str(ATTR___ERASE__))) {
        memory_reset_hww();
        commander_clear_report();
        commander_fill_report(cmd_str(CMD_reset), attr_str(ATTR_success), DBB_OK);
        return;
    }

    commander_fill_report(cmd_str(CMD_reset), NULL, DBB_ERR_IO_INVALID_CMD);
}


static void commander_process_name(yajl_val json_node)
{
    const char *path[] = { cmd_str(CMD_name), NULL };
    const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));

    if (strlens(value) &&
            utils_limit_alphanumeric_hyphen_underscore_period(value) != DBB_OK) {
        commander_fill_report(cmd_str(CMD_name), NULL, DBB_ERR_SD_BAD_CHAR);
        return;
    }

    commander_fill_report(cmd_str(CMD_name), (char *)memory_name(value), DBB_OK);
}


static int commander_process_aes_key(const char *message, int msg_len, PASSWORD_ID id)
{
    return (memory_write_aeskey(message, msg_len, id));
}


static int commander_process_backup_check(const char *key, const char *filename,
        const char *source)
{
    int ret;
    HDNode node;
    uint8_t backup_hww[MEM_PAGE_LEN];
    uint8_t backup_u2f[MEM_PAGE_LEN];
    char *backup_u2f_hex;
    char *backup_hex;

    if (!strlens(source)) {
        commander_fill_report(cmd_str(CMD_backup), NULL, DBB_ERR_IO_INVALID_CMD);
        return DBB_ERROR;
    }

    if (
        (!STREQ(source, attr_str(ATTR_U2F))) &&
        (!STREQ(source, attr_str(ATTR_HWW))) &&
        (!STREQ(source, attr_str(ATTR_all)))) {
        commander_fill_report(cmd_str(CMD_backup), NULL, DBB_ERR_IO_INVALID_CMD);
        return DBB_ERROR;
    }

    backup_hex = sd_load(filename, CMD_backup);

    if (strlens(backup_hex) < MEM_PAGE_LEN * 2) {
        commander_fill_report(cmd_str(CMD_backup), NULL, DBB_ERR_SD_READ_FILE);
        utils_zero(backup_hex, strlens(backup_hex));
        return DBB_ERROR;
    }

    // u2f | all
    if (STREQ(source, attr_str(ATTR_U2F)) || STREQ(source, attr_str(ATTR_all))) {
        backup_u2f_hex = strchr(backup_hex, SD_PDF_DELIM2);
        if (!strlens(backup_u2f_hex)) {
            ret = DBB_ERROR;
        } else {
            memcpy(backup_u2f, utils_hex_to_uint8(backup_u2f_hex + strlens(SD_PDF_DELIM2_S)),
                   sizeof(backup_u2f));
            ret = !MEMEQ(backup_u2f, memory_master_u2f(NULL), MEM_PAGE_LEN) ? DBB_ERROR : DBB_OK;
        }
    } else {
        ret = DBB_OK;
    }

    // hww | all
    if ((ret == DBB_OK) && (STREQ(source, attr_str(ATTR_HWW)) ||
                            STREQ(source, attr_str(ATTR_all)))) {
        memcpy(backup_hww, utils_hex_to_uint8(backup_hex), sizeof(backup_hww));
        if (MEMEQ(backup_hww, MEM_PAGE_ERASE, MEM_PAGE_LEN)) {
            ret = DBB_ERROR;
        } else if (!MEMEQ(backup_hww, memory_master_hww_entropy(NULL), MEM_PAGE_LEN)) {
            ret = DBB_ERROR;
        } else {
            // entropy matches, check if derived master and chaincodes match
            char seed[MEM_PAGE_LEN * 2 + 1];
            snprintf(seed, sizeof(seed), "%s", utils_uint8_to_hex(backup_hww, MEM_PAGE_LEN));
            if (wallet_generate_node(key, seed, &node) == DBB_ERROR) {
                ret = DBB_ERROR;
            } else {
                uint8_t main_ok = MEMEQ(node.private_key, memory_master_hww(NULL), MEM_PAGE_LEN) && MEMEQ(node.chain_code, memory_master_hww_chaincode(NULL), MEM_PAGE_LEN);
                uint8_t hidden_ok = MEMEQ(node.private_key, memory_hidden_hww(NULL), MEM_PAGE_LEN) && MEMEQ(node.chain_code, memory_hidden_hww_chaincode(NULL), MEM_PAGE_LEN);
                ret = (main_ok | hidden_ok) ? DBB_OK : DBB_ERROR; // bitwise for constant time
            }
            utils_zero(seed, sizeof(seed));
        }
    }

    utils_zero(backup_hex, strlens(backup_hex));
    utils_zero(backup_hww, sizeof(backup_hww));
    utils_zero(backup_u2f, sizeof(backup_u2f));
    utils_zero(&node, sizeof(HDNode));

    if (ret == DBB_OK) {
        commander_fill_report(cmd_str(CMD_backup), attr_str(ATTR_success), DBB_OK);
    } else {
        commander_fill_report(cmd_str(CMD_backup), NULL, DBB_ERR_SD_NO_MATCH);
    }
    return ret;
}


static int commander_process_backup_create(const char *key, const char *filename,
        const char *source)
{
    int ret;
    uint8_t backup_hww[MEM_PAGE_LEN];
    uint8_t backup_u2f[MEM_PAGE_LEN];
    char backup_hww_hex[MEM_PAGE_LEN * 2 + 1];
    char backup_u2f_hex[MEM_PAGE_LEN * 2 + 1];
    char *name = (char *)memory_name("");

    memset(backup_hww_hex, 0, sizeof(backup_hww_hex));
    memset(backup_u2f_hex, 0, sizeof(backup_u2f_hex));

    if (wallet_seeded() != DBB_OK) {
        commander_fill_report(cmd_str(CMD_backup), NULL, DBB_ERR_KEY_MASTER);
        return DBB_ERROR;
    }

    if (STREQ(source, attr_str(ATTR_HWW)) || STREQ(source, attr_str(ATTR_all))) {
        memcpy(backup_hww, memory_master_hww_entropy(NULL), MEM_PAGE_LEN);
        snprintf(backup_hww_hex, sizeof(backup_hww_hex), "%s", utils_uint8_to_hex(backup_hww,
                 sizeof(backup_hww)));
    }

    if (STREQ(source, attr_str(ATTR_U2F)) || STREQ(source, attr_str(ATTR_all))) {
        memcpy(backup_u2f, memory_report_master_u2f(), MEM_PAGE_LEN);
        snprintf(backup_u2f_hex, sizeof(backup_u2f_hex), "%s", utils_uint8_to_hex(backup_u2f,
                 sizeof(backup_u2f)));
    }

    ret = sd_write(filename, backup_hww_hex, name, backup_u2f_hex, DBB_SD_NO_REPLACE,
                   CMD_backup);

    utils_zero(backup_hww, sizeof(backup_hww));
    utils_zero(backup_hww_hex, sizeof(backup_hww_hex));
    utils_zero(backup_u2f, sizeof(backup_u2f));
    utils_zero(backup_u2f_hex, sizeof(backup_u2f_hex));

    if (ret != DBB_OK) {
        /* error reported in sd_write() */
        return ret;
    }

    return commander_process_backup_check(key, filename, source);
}


static void commander_process_backup(yajl_val json_node)
{
    const char *filename_path[] = { cmd_str(CMD_backup), cmd_str(CMD_filename), NULL };
    const char *source_path[] = { cmd_str(CMD_backup), cmd_str(CMD_source), NULL };
    const char *value_path[] = { cmd_str(CMD_backup), NULL };
    const char *erase_path[] = { cmd_str(CMD_backup), cmd_str(CMD_erase), NULL };
    const char *check_path[] = { cmd_str(CMD_backup), cmd_str(CMD_check), NULL };
    const char *key_path[] = { cmd_str(CMD_backup), cmd_str(CMD_key), NULL };
    const char *filename = YAJL_GET_STRING(yajl_tree_get(json_node, filename_path,
                                           yajl_t_string));
    const char *source_y = YAJL_GET_STRING(yajl_tree_get(json_node, source_path,
                                           yajl_t_string));
    const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, value_path, yajl_t_string));
    const char *erase = YAJL_GET_STRING(yajl_tree_get(json_node, erase_path, yajl_t_string));
    const char *check = YAJL_GET_STRING(yajl_tree_get(json_node, check_path, yajl_t_string));
    const char *key = YAJL_GET_STRING(yajl_tree_get(json_node, key_path, yajl_t_string));
    char source[MAX(MAX(strlens(attr_str(ATTR_U2F)), strlens(attr_str(ATTR_HWW))),
                                                         strlens(attr_str(ATTR_all))) + 1];

    if (wallet_is_locked()) {
        commander_fill_report(cmd_str(CMD_backup), NULL, DBB_ERR_IO_LOCKED);
        return;
    }

    if (strlens(value)) {
        if (STREQ(value, attr_str(ATTR_list))) {
            sd_list(CMD_backup);
            return;
        }

        commander_fill_report(cmd_str(CMD_backup), NULL, DBB_ERR_IO_INVALID_CMD);
        return;
    }

    if (strlens(erase)) {
        // Erase single file
        int status = touch_button_press(DBB_TOUCH_LONG);
        if (status == DBB_TOUCHED) {
            sd_erase(CMD_backup, erase);
        } else {
            commander_fill_report(cmd_str(CMD_backup), NULL, status);
        }
        return;
    }

    if (strlens(source_y)) {
        snprintf(source, sizeof(source), "%s", source_y);
    } else {
        // Defaults
        if (check) {
            snprintf(source, sizeof(source), "%s", attr_str(ATTR_HWW));// Backward compatible
        } else {
            snprintf(source, sizeof(source), "%s", attr_str(ATTR_all));
        }
    }

    if (!strlens(key) && !STREQ(source, attr_str(ATTR_U2F))) {
        // Exit if backing up HWW but no key given
        commander_fill_report(cmd_str(CMD_seed), NULL, DBB_ERR_SD_KEY);
        return;
    }

    if (check) {
        // Verify existing backup
        if (STREQ(source, attr_str(ATTR_all))) {
            commander_fill_report(cmd_str(CMD_backup), NULL, DBB_ERR_IO_INVALID_CMD);
            return;
        }
        commander_process_backup_check(key, check, source);
        return;
    }

    if (filename) {
        // Create new backup
        commander_process_backup_create(key, filename, source);
        return;
    }

    commander_fill_report(cmd_str(CMD_backup), NULL, DBB_ERR_IO_INVALID_CMD);
}


static void commander_process_seed(yajl_val json_node)
{
    int ret;

    const char *key_path[] = { cmd_str(CMD_seed), cmd_str(CMD_key), NULL };
    const char *source_path[] = { cmd_str(CMD_seed), cmd_str(CMD_source), NULL };
    const char *entropy_path[] = { cmd_str(CMD_seed), cmd_str(CMD_entropy), NULL };
    const char *filename_path[] = { cmd_str(CMD_seed), cmd_str(CMD_filename), NULL };
    const char *u2f_counter_path[] = { cmd_str(CMD_seed), cmd_str(CMD_U2F_counter), NULL };
    const char *key = YAJL_GET_STRING(yajl_tree_get(json_node, key_path, yajl_t_string));
    const char *source = YAJL_GET_STRING(yajl_tree_get(json_node, source_path,
                                         yajl_t_string));
    const char *entropy = YAJL_GET_STRING(yajl_tree_get(json_node, entropy_path,
                                          yajl_t_string));
    const char *filename = YAJL_GET_STRING(yajl_tree_get(json_node, filename_path,
                                           yajl_t_string));
    yajl_val u2f_counter_data = yajl_tree_get(json_node, u2f_counter_path,
                                yajl_t_number);

    if (wallet_is_locked()) {
        commander_fill_report(cmd_str(CMD_seed), NULL, DBB_ERR_IO_LOCKED);
        return;
    }

    if (!strlens(source) || !strlens(filename)) {
        commander_fill_report(cmd_str(CMD_seed), NULL, DBB_ERR_IO_INVALID_CMD);
        return;
    }

    if (!strlens(key) && !STREQ(source, attr_str(ATTR_U2F_load))) {
        commander_fill_report(cmd_str(CMD_seed), NULL, DBB_ERR_SD_KEY);
        return;
    }

    if (sd_card_inserted() != DBB_OK) {
        commander_fill_report(cmd_str(CMD_seed), NULL, DBB_ERR_SEED_SD);
        return;
    }

    if (utils_limit_alphanumeric_hyphen_underscore_period(filename) != DBB_OK) {
        commander_fill_report(cmd_str(CMD_seed), NULL, DBB_ERR_SD_BAD_CHAR);
        return;
    }

    if (STREQ(source, attr_str(ATTR_create))) {
        // Generate a new wallet, optionally with entropy entered via USB
        uint8_t i, add_entropy = 1, entropy_b[MEM_PAGE_LEN];
        char entropy_c[MEM_PAGE_LEN * 2 + 1];

        memset(entropy_b, 0, sizeof(entropy_b));

        if (sd_file_exists(filename) == DBB_OK) {
            commander_fill_report(cmd_str(CMD_seed), NULL, DBB_ERR_SD_OPEN_FILE);
            return;
        }

        if (strlens(entropy)) {
            if (strlens(entropy) != SHA256_DIGEST_LENGTH * 2) {
                commander_fill_report(cmd_str(CMD_seed), NULL, DBB_ERR_IO_INVALID_CMD);
                return;
            }
            sha256_Raw((const uint8_t *)entropy, strlens(entropy), entropy_b);
        }

#ifdef TESTING
        // Add extra entropy from device unless raw is set
        const char *raw_path[] = { cmd_str(CMD_seed), cmd_str(CMD_raw), NULL };
        const char *raw = YAJL_GET_STRING(yajl_tree_get(json_node, raw_path, yajl_t_string));
        if (strlens(entropy) && strlens(raw)) {
            if (STREQ(raw, attr_str(ATTR_true))) {
                add_entropy = 0;
            }
        }
#endif

        if (add_entropy) {
            uint8_t number[MEM_PAGE_LEN];
            if (random_bytes(number, sizeof(number), 1) == DBB_ERROR) {
                commander_fill_report(cmd_str(CMD_seed), NULL, DBB_ERR_MEM_ATAES);
                utils_zero(entropy_b, sizeof(entropy_b));
                return;
            }
            for (i = 0; i < MEM_PAGE_LEN; i++) {
                entropy_b[i] ^= number[i];
            }
            sha256_Raw(entropy_b, sizeof(entropy_b), entropy_b);
        }

        snprintf(entropy_c, sizeof(entropy_c), "%s", utils_uint8_to_hex(entropy_b,
                 sizeof(entropy_b)));
        ret = wallet_create(key, entropy_c);
        if (ret == DBB_OK) {
            if (commander_process_backup_create(key, filename, attr_str(ATTR_all)) != DBB_OK) {
                memory_erase_hww_seed();
                utils_zero(entropy_b, sizeof(entropy_b));
                utils_zero(entropy_c, sizeof(entropy_c));
                return;
            }
        }

        utils_zero(entropy_b, sizeof(entropy_b));
        utils_zero(entropy_c, sizeof(entropy_c));
    }

    else if (STREQ(source, attr_str(ATTR_U2F_create))) {
        memory_reset_u2f();
        ret = commander_process_backup_create(key, filename, attr_str(ATTR_all));
        if (ret == DBB_OK && YAJL_IS_INTEGER(u2f_counter_data)) {
            memory_u2f_count_set(YAJL_GET_INTEGER(u2f_counter_data));
        }
    }

    else if (STREQ(source, attr_str(ATTR_backup)) ||
             STREQ(source, attr_str(ATTR_U2F_load))) {
        char entropy_c[MEM_PAGE_LEN * 2 + 1];
        char *backup_hex = sd_load(filename, CMD_seed);
        char *name = strchr(backup_hex, SD_PDF_DELIM);
        char *u2f = strchr(backup_hex, SD_PDF_DELIM2);

        if (STREQ(source, attr_str(ATTR_U2F_load))) {
            if (strlens(u2f)) {
                uint8_t backup_u2f[MEM_PAGE_LEN];
                memcpy(backup_u2f, utils_hex_to_uint8(u2f + strlens(SD_PDF_DELIM2_S)),
                       sizeof(backup_u2f));
                memory_master_u2f(backup_u2f);
                if (YAJL_IS_INTEGER(u2f_counter_data)) {
                    memory_u2f_count_set(YAJL_GET_INTEGER(u2f_counter_data));
                }
                ret = DBB_OK;
            } else {
                ret = DBB_ERROR;
            }
        } else {
            if (strlens(backup_hex) < MEM_PAGE_LEN * 2) {
                ret = DBB_ERROR;
            } else if (strlens(name) && strlens(u2f) ?
                       (name != backup_hex + MEM_PAGE_LEN * 4 + strlens(SD_PDF_DELIM2_S)) :
                       (name != backup_hex + MEM_PAGE_LEN * 2)) {
                ret = DBB_ERROR;
            } else if (!strlens(name) ? (strlens(backup_hex) != MEM_PAGE_LEN * 2) : 0) {
                ret = DBB_ERROR;
            } else {
                if (strlens(name) > 1) {
                    memory_name(name + 1);
                }
                snprintf(entropy_c, sizeof(entropy_c), "%s", backup_hex);
                ret = wallet_create(key, entropy_c);
                if (ret == DBB_OK) {
                    if (commander_process_backup_check(key, filename, attr_str(ATTR_HWW)) != DBB_OK) {
                        memory_erase_hww_seed();
                        utils_zero(backup_hex, strlens(backup_hex));
                        utils_zero(entropy_c, sizeof(entropy_c));
                        return;
                    }
                }
            }
        }
        utils_zero(backup_hex, strlens(backup_hex));
        utils_zero(entropy_c, sizeof(entropy_c));
    }

    else {
        commander_fill_report(cmd_str(CMD_seed), NULL, DBB_ERR_IO_INVALID_CMD);
        return;
    }

    if (ret == DBB_ERROR) {
        commander_fill_report(cmd_str(CMD_seed), NULL, DBB_ERR_SEED_INVALID);
    } else if (ret == DBB_ERROR_MEM) {
        commander_fill_report(cmd_str(CMD_seed), NULL, DBB_ERR_MEM_ATAES);
    } else if (ret == DBB_OK) {
        commander_clear_report();
        commander_fill_report(cmd_str(CMD_seed), attr_str(ATTR_success), DBB_OK);
    } else {
        commander_fill_report(cmd_str(CMD_seed), NULL, ret);
    }
}


static int commander_process_sign(yajl_val json_node)
{
    size_t i;
    int ret;
    const char *data_path[] = { cmd_str(CMD_sign), cmd_str(CMD_data), NULL };
    yajl_val data = yajl_tree_get(json_node, data_path, yajl_t_array);

    if (!YAJL_IS_ARRAY(data) || data->u.array.len == 0) {
        commander_fill_report(cmd_str(CMD_sign), NULL, DBB_ERR_IO_INVALID_CMD);
        return DBB_ERROR;
    }

    memset(json_array, 0, COMMANDER_ARRAY_MAX);
    for (i = 0; i < data->u.array.len; i++) {
        const char *keypath_path[] = { cmd_str(CMD_keypath), NULL };
        const char *hash_path[] = { cmd_str(CMD_hash), NULL };

        yajl_val obj = data->u.array.values[i];
        const char *keypath = YAJL_GET_STRING(yajl_tree_get(obj, keypath_path, yajl_t_string));
        const char *hash = YAJL_GET_STRING(yajl_tree_get(obj, hash_path, yajl_t_string));

        if (!hash || !keypath) {
            commander_fill_report(cmd_str(CMD_sign), NULL, DBB_ERR_IO_INVALID_CMD);
            return DBB_ERROR;
        }

        ret = wallet_sign(hash, keypath);
        if (ret != DBB_OK) {
            return ret;
        };
    }
    commander_fill_report(cmd_str(CMD_sign), json_array, DBB_JSON_ARRAY);
    memset(json_array, 0, COMMANDER_ARRAY_MAX);
    return ret;
}


static void commander_process_random(yajl_val json_node)
{
    int update_seed;
    uint8_t number[16];

    int encrypt_len;
    char *encoded_report;
    char echo_number[32 + 13 + 1];

    const char *path[] = { cmd_str(CMD_random), NULL };
    const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));

    if (!strlens(value)) {
        commander_fill_report(cmd_str(CMD_random), NULL, DBB_ERR_IO_INVALID_CMD);
        return;
    }

    if (STREQ(value, attr_str(ATTR_true))) {
        update_seed = 1;
    } else if (STREQ(value, attr_str(ATTR_pseudo))) {
        update_seed = 0;
    } else {
        commander_fill_report(cmd_str(CMD_random), NULL, DBB_ERR_IO_INVALID_CMD);
        return;
    }

    if (random_bytes(number, sizeof(number), update_seed) == DBB_ERROR) {
        commander_fill_report(cmd_str(CMD_random), NULL, DBB_ERR_MEM_ATAES);
        return;
    }

    commander_fill_report(cmd_str(CMD_random), utils_uint8_to_hex(number, sizeof(number)),
                          DBB_OK);

    snprintf(echo_number, sizeof(echo_number), "{\"random\":\"%s\"}",
             utils_uint8_to_hex(number, sizeof(number)));

    encoded_report = cipher_aes_b64_hmac_encrypt((unsigned char *) echo_number,
                     strlens(echo_number), &encrypt_len,
                     memory_report_aeskey(TFA_SHARED_SECRET));

    if (encoded_report) {
        commander_fill_report(cmd_str(CMD_echo), encoded_report, DBB_OK);
        free(encoded_report);
    } else {
        commander_clear_report();
        commander_fill_report(cmd_str(CMD_random), NULL, DBB_ERR_MEM_ENCRYPT);
    }
}


static void commander_process_ecdh(yajl_val json_node)
{
    if (wallet_is_locked()) {
        commander_fill_report(cmd_str(CMD_ecdh), NULL, DBB_ERR_IO_LOCKED);
        return;
    }

    ecdh_dispatch_command(json_node);
}


static void commander_process_xpub(yajl_val json_node)
{
    char xpub[112] = {0};
    const char *path[] = { cmd_str(CMD_xpub), NULL };
    const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));

    if (!strlens(value)) {
        commander_fill_report(cmd_str(CMD_xpub), NULL, DBB_ERR_IO_INVALID_CMD);
        return;
    }

    wallet_report_xpub(value, xpub);

    if (xpub[0]) {
        commander_fill_report(cmd_str(CMD_xpub), xpub, DBB_OK);

        int encrypt_len;
        char *encoded_report = cipher_aes_b64_hmac_encrypt((unsigned char *) xpub, strlens(xpub),
                               &encrypt_len, memory_report_aeskey(TFA_SHARED_SECRET));

        if (encoded_report) {
            commander_fill_report(cmd_str(CMD_echo), encoded_report, DBB_OK);
            free(encoded_report);
        } else {
            commander_clear_report();
            commander_fill_report(cmd_str(CMD_xpub), NULL, DBB_ERR_MEM_ENCRYPT);
        }
    } else {
        commander_fill_report(cmd_str(CMD_xpub), NULL, DBB_ERR_KEY_CHILD);
    }
}


static uint8_t commander_bootloader_unlocked(void)
{
    uint8_t sig[FLASH_SIG_LEN];
    flash_wrapper_read_sig_area(sig, FLASH_SIG_START, FLASH_SIG_LEN);
    return sig[FLASH_BOOT_LOCK_BYTE];
}


static void commander_process_device(yajl_val json_node)
{
    const char *path[] = { cmd_str(CMD_device), NULL };
    const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));

    if (!strlens(value)) {
        commander_fill_report(cmd_str(CMD_device), NULL, DBB_ERR_IO_INVALID_CMD);
        return;
    }

    if (STREQ(value, attr_str(ATTR_lock))) {
        if (wallet_seeded() == DBB_OK) {
            int status = touch_button_press(DBB_TOUCH_LONG);
            if (status == DBB_TOUCHED) {
                char msg[256];
                memory_write_unlocked(0);
                snprintf(msg, sizeof(msg), "{\"%s\":%s}", attr_str(ATTR_lock), attr_str(ATTR_true));
                commander_fill_report(cmd_str(CMD_device), msg, DBB_JSON_ARRAY);
            } else {
                commander_fill_report(cmd_str(CMD_device), NULL, status);
            }
        } else {
            commander_fill_report(cmd_str(CMD_device), NULL, DBB_ERR_KEY_MASTER);
        }
        return;
    }

    if (STREQ(value, attr_str(ATTR_info))) {
        char msg[1024];
        char id[65] = {0};
        char lock[6] = {0};
        char seeded[6] = {0};
        char sdcard[6] = {0};
        char bootlock[6] = {0};
        char u2f_enabled[6] = {0};
        char u2f_hijack_enabled[6] = {0};
        char new_hidden_wallet_enabled[6] = {0};
        char pairing_enabled[6] = {0};
        uint32_t serial[4] = {0};

        flash_wrapper_read_unique_id(serial, 4);

        if (wallet_is_locked()) {
            snprintf(lock, sizeof(lock), "%s", attr_str(ATTR_true));
        } else {
            snprintf(lock, sizeof(lock), "%s", attr_str(ATTR_false));
        }

        if (wallet_seeded() == DBB_OK) {
            snprintf(seeded, sizeof(seeded), "%s", attr_str(ATTR_true));
            wallet_report_id(id);
        } else {
            snprintf(seeded, sizeof(seeded), "%s", attr_str(ATTR_false));
        }

        if (commander_bootloader_unlocked()) {
            snprintf(bootlock, sizeof(bootlock), "%s", attr_str(ATTR_false));
        } else {
            snprintf(bootlock, sizeof(bootlock), "%s", attr_str(ATTR_true));
        }

        uint32_t ext_flags = memory_report_ext_flags();
        if (ext_flags & MEM_EXT_MASK_U2F) {
            // Bit is set == enabled
            snprintf(u2f_enabled, sizeof(u2f_enabled), "%s", attr_str(ATTR_true));
        } else {
            snprintf(u2f_enabled, sizeof(u2f_enabled), "%s", attr_str(ATTR_false));
        }
        if (ext_flags & MEM_EXT_MASK_U2F_HIJACK) {
            // Bit is set == enabled
            snprintf(u2f_hijack_enabled, sizeof(u2f_hijack_enabled), "%s", attr_str(ATTR_true));
        } else {
            snprintf(u2f_hijack_enabled, sizeof(u2f_hijack_enabled), "%s", attr_str(ATTR_false));
        }

        if (ext_flags & MEM_EXT_MASK_NEW_HIDDEN_WALLET) {
            // Bit is set == enabled
            snprintf(new_hidden_wallet_enabled, sizeof(new_hidden_wallet_enabled), "%s", attr_str(ATTR_true));
        } else {
            snprintf(new_hidden_wallet_enabled, sizeof(new_hidden_wallet_enabled), "%s", attr_str(ATTR_false));
        }

        if (wallet_is_paired()) {
            snprintf(pairing_enabled, sizeof(pairing_enabled), "%s", attr_str(ATTR_true));
        } else {
            snprintf(pairing_enabled, sizeof(pairing_enabled), "%s", attr_str(ATTR_false));
        }


        if (sd_card_inserted() == DBB_OK) {
            snprintf(sdcard, sizeof(sdcard), "%s", attr_str(ATTR_true));
        } else {
            snprintf(sdcard, sizeof(sdcard), "%s", attr_str(ATTR_false));
        }

        int tfa_len;

        char *tfa = cipher_aes_b64_hmac_encrypt((const unsigned char *)VERIFYPASS_CRYPT_TEST,
                                                strlens(VERIFYPASS_CRYPT_TEST), &tfa_len,
                                                memory_report_aeskey(TFA_SHARED_SECRET));
        if (!tfa) {
            commander_clear_report();
            commander_fill_report(cmd_str(CMD_device), NULL, DBB_ERR_MEM_ENCRYPT);
            return;
        }

        snprintf(msg, sizeof(msg),
                 "{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":%s,\"%s\":%s,\"%s\":%s,\"%s\":%s,\"%s\":\"%s\",\"%s\":%s,\"%s\":%s,\"%s\":%s,\"%s\":%s}",
                 attr_str(ATTR_serial), utils_uint8_to_hex((uint8_t *)serial, sizeof(serial)),
                 attr_str(ATTR_version), DIGITAL_BITBOX_VERSION,
                 attr_str(ATTR_name), (char *)memory_name(""),
                 attr_str(ATTR_id), id,
                 attr_str(ATTR_seeded), seeded,
                 attr_str(ATTR_lock), lock,
                 attr_str(ATTR_bootlock), bootlock,
                 attr_str(ATTR_sdcard), sdcard,
                 attr_str(ATTR_TFA), tfa,
                 attr_str(ATTR_U2F), u2f_enabled,
                 attr_str(ATTR_U2F_hijack), u2f_hijack_enabled,
                 attr_str(ATTR_new_hidden_wallet), new_hidden_wallet_enabled,
                 attr_str(ATTR_pairing), pairing_enabled);

        free(tfa);
        commander_fill_report(cmd_str(CMD_device), msg, DBB_JSON_ARRAY);
        return;
    }

    commander_fill_report(cmd_str(CMD_device), NULL, DBB_ERR_IO_INVALID_CMD);
}


static void commander_process_led(yajl_val json_node)
{
    const char *path[] = { cmd_str(CMD_led), NULL };
    const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));

    if (!strlens(value)) {
        commander_fill_report(cmd_str(CMD_led), NULL, DBB_ERR_IO_INVALID_CMD);
        return;
    }

    if (STREQ(value, attr_str(ATTR_blink))) {
        led_abort();
        commander_fill_report(cmd_str(CMD_led), attr_str(ATTR_success), DBB_OK);
    } else {
        commander_fill_report(cmd_str(CMD_led), NULL, DBB_ERR_IO_INVALID_CMD);
    }
}


static void commander_process_feature_set(yajl_val json_node)
{
    const char *path[] = { cmd_str(CMD_feature_set), NULL };
    yajl_val data = yajl_tree_get(json_node, path, yajl_t_any);

    if (!YAJL_IS_OBJECT(data) || data->u.object.len <= 0) {
        commander_clear_report();
        goto err;
    } else {
        uint32_t flags = memory_report_ext_flags();
        const char *u2f_path[] = { cmd_str(CMD_U2F), NULL };
        const char *u2f_hijack_path[] = { cmd_str(CMD_U2F_hijack), NULL };
        const char *new_hidden_wallet_path[] = { attr_str(ATTR_new_hidden_wallet), NULL };
        const char *pairing_path[] = { attr_str(ATTR_pairing), NULL };
        yajl_val u2f = yajl_tree_get(data, u2f_path, yajl_t_any);
        yajl_val u2f_hijack = yajl_tree_get(data, u2f_hijack_path, yajl_t_any);
        yajl_val new_hidden_wallet = yajl_tree_get(data, new_hidden_wallet_path, yajl_t_any);
        yajl_val pairing = yajl_tree_get(data, pairing_path, yajl_t_any);

        if (!u2f && !u2f_hijack && !new_hidden_wallet && !pairing) {
            goto err;
        }

        // Set the bit == enabled
        if (u2f) {
            if (YAJL_IS_TRUE(u2f)) {
                flags |= MEM_EXT_MASK_U2F;
            } else if (YAJL_IS_FALSE(u2f)) {
                flags &= ~(MEM_EXT_MASK_U2F);
            } else {
                goto err;
            }
        }

        // Set the bit == enabled
        if (u2f_hijack) {
            if (YAJL_IS_TRUE(u2f_hijack)) {
                flags |= MEM_EXT_MASK_U2F_HIJACK;
            } else if (YAJL_IS_FALSE(u2f_hijack)) {
                flags &= ~(MEM_EXT_MASK_U2F_HIJACK);
            } else {
                goto err;
            }
        }

        // Set the bit == enabled
        if (new_hidden_wallet) {
            if (wallet_is_locked()) {
                commander_fill_report(cmd_str(CMD_feature_set), NULL, DBB_ERR_IO_LOCKED);
                return;
            }

            if (YAJL_IS_TRUE(new_hidden_wallet)) {
                flags |= MEM_EXT_MASK_NEW_HIDDEN_WALLET;
            } else if (YAJL_IS_FALSE(new_hidden_wallet)) {
                flags &= ~(MEM_EXT_MASK_NEW_HIDDEN_WALLET);
            } else {
                goto err;
            }
        }

        // Set the bit == enabled
        if (pairing) {
            if (YAJL_IS_TRUE(pairing)) {
                flags &= ~(MEM_EXT_MASK_NOTPAIRED);
            } else {
                goto err;
            }
        }

        memory_write_ext_flags(flags);
        commander_fill_report(cmd_str(CMD_feature_set), attr_str(ATTR_success), DBB_OK);
        return;
    }

err:
    commander_fill_report(cmd_str(CMD_feature_set), NULL, DBB_ERR_IO_INVALID_CMD);
}


static void commander_process_bootloader(yajl_val json_node)
{
    const char *path[] = { cmd_str(CMD_bootloader), NULL };
    const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));

    if (!strlens(value)) {
        commander_fill_report(cmd_str(CMD_bootloader), NULL, DBB_ERR_IO_INVALID_CMD);
        return;
    }

    uint8_t sig[FLASH_SIG_LEN];
    flash_wrapper_read_sig_area(sig, FLASH_SIG_START, FLASH_SIG_LEN);

    if (STREQ(value, attr_str(ATTR_lock))) {
        sig[FLASH_BOOT_LOCK_BYTE] = 0;
    } else if (STREQ(value, attr_str(ATTR_unlock))) {
        sig[FLASH_BOOT_LOCK_BYTE] = 0xFF;
    } else {
        commander_fill_report(cmd_str(CMD_bootloader), NULL, DBB_ERR_IO_INVALID_CMD);
        return;
    }

    if (flash_wrapper_erase_page(FLASH_SIG_START, IFLASH_ERASE_PAGES_8) != FLASH_RC_OK) {
        goto err;
    }

    if (flash_wrapper_write(FLASH_SIG_START, sig, FLASH_SIG_LEN, 0) != FLASH_RC_OK) {
        goto err;
    }

    commander_fill_report(cmd_str(CMD_bootloader), value, DBB_OK);
    return;

err:
    commander_fill_report(cmd_str(CMD_bootloader), NULL, DBB_ERR_MEM_FLASH);
}


static uint8_t commander_check_password_collision(void)
{
    if (MEMEQ(memory_report_aeskey(PASSWORD_STAND), memory_report_aeskey(PASSWORD_HIDDEN),
              MEM_PAGE_LEN)) {
        memory_active_key_set(memory_report_aeskey(PASSWORD_STAND));
        memory_random_password(PASSWORD_HIDDEN);
        memory_hidden_hww_chaincode(MEM_PAGE_ERASE_FE);
        memory_hidden_hww(MEM_PAGE_ERASE_FE);
        commander_fill_report(cmd_str(CMD_password), NULL, DBB_ERR_IO_PW_COLLIDE);
        return DBB_ERROR;
    }
    return DBB_OK;
}


static void commander_process_hidden_password(yajl_val json_node)
{
    const char *pw_path[] = {cmd_str(CMD_hidden_password), cmd_str(CMD_password), NULL };
    const char *key_path[] = {cmd_str(CMD_hidden_password), cmd_str(CMD_key), NULL };
    const char *pw = YAJL_GET_STRING(yajl_tree_get(json_node, pw_path, yajl_t_string));
    const char *key = YAJL_GET_STRING(yajl_tree_get(json_node, key_path, yajl_t_string));

    HDNode node;
    uint8_t ret;
    char seed[MEM_PAGE_LEN * 2 + 1];

    if (wallet_is_locked()) {
        commander_fill_report(cmd_str(CMD_hidden_password), NULL, DBB_ERR_IO_LOCKED);
        return;
    }

    if (wallet_seeded() != DBB_OK) {
        commander_fill_report(cmd_str(CMD_hidden_password), NULL, DBB_ERR_KEY_MASTER);
        return;
    }

    if (wallet_is_hidden()) {
        /* should never enter */
        commander_fill_report(cmd_str(CMD_hidden_password), NULL, DBB_ERR_IO_LOCKED);
        return;
    }

    if (!strlens(key) || !strlens(pw)) {
        commander_fill_report(cmd_str(CMD_hidden_password), NULL, DBB_ERR_IO_INVALID_CMD);
        return;
    }

    ret = commander_process_aes_key(pw, strlens(pw), PASSWORD_HIDDEN);

    if (ret != DBB_OK) {
        commander_fill_report(cmd_str(CMD_hidden_password), NULL, ret);
        return;
    }

    if (commander_check_password_collision() != DBB_OK) {
        return;
    }

    snprintf(seed, sizeof(seed), "%s", utils_uint8_to_hex(memory_master_hww_entropy(NULL),
             MEM_PAGE_LEN));
    if (wallet_generate_node(key, seed, &node) == DBB_ERROR) {
        commander_fill_report(cmd_str(CMD_hidden_password), NULL, DBB_ERR_MEM_ATAES);
        return;
    }
    memory_hidden_hww(node.private_key);
    memory_hidden_hww_chaincode(node.chain_code);

    commander_fill_report(cmd_str(CMD_hidden_password), attr_str(ATTR_success), DBB_OK);
}


static void commander_process_password(yajl_val json_node)
{
    int ret;
    const char *pw_path[] = { cmd_str(CMD_password), NULL };
    const char *pw = YAJL_GET_STRING(yajl_tree_get(json_node, pw_path, yajl_t_string));

    ret = wallet_is_hidden() ?
          commander_process_aes_key(pw, strlens(pw), PASSWORD_HIDDEN) :
          commander_process_aes_key(pw, strlens(pw), PASSWORD_STAND);

    if (ret != DBB_OK) {
        commander_fill_report(cmd_str(CMD_password), NULL, ret);
        return;
    }

    if (commander_check_password_collision() != DBB_OK) {
        return;
    }

    commander_fill_report(cmd_str(CMD_password), attr_str(ATTR_success), DBB_OK);
}


static int commander_process(int cmd, yajl_val json_node)
{
    switch (cmd) {
        case CMD_reset:
            commander_process_reset(json_node);
            return DBB_RESET;

        case CMD_hidden_password:
            commander_process_hidden_password(json_node);
            break;

        case CMD_password:
            commander_process_password(json_node);
            break;

        case CMD_ecdh:
            commander_process_ecdh(json_node);
            break;

        case CMD_led:
            commander_process_led(json_node);
            break;

        case CMD_name:
            commander_process_name(json_node);
            break;

        case CMD_seed:
            commander_process_seed(json_node);
            break;

        case CMD_backup:
            commander_process_backup(json_node);
            break;

        case CMD_random:
            commander_process_random(json_node);
            break;

        case CMD_xpub:
            commander_process_xpub(json_node);
            break;

        case CMD_device:
            commander_process_device(json_node);
            break;

        case CMD_bootloader:
            commander_process_bootloader(json_node);
            break;

        case CMD_feature_set:
            commander_process_feature_set(json_node);
            break;

        default: {
            /* never reached */
        }
    }
    return DBB_OK;
}


//
//  Handle API input (preprocessing) //
//

static int commander_tfa_append_pin(void)
{
    // Create one-time PIN
    uint8_t pin_b[TFA_PIN_LEN];
    memset(TFA_PIN, 0, sizeof(TFA_PIN));
    if (random_bytes(pin_b, TFA_PIN_LEN, 0) == DBB_ERROR) {
        commander_fill_report(cmd_str(CMD_random), NULL, DBB_ERR_MEM_ATAES);
        return DBB_ERROR;
    }

    // Note: if you change this to binary, be sure to update the TFA_PIN check
    // in commander_parse().
#ifdef TESTING
    snprintf(TFA_PIN, sizeof(TFA_PIN), "0001");
#else

    snprintf(TFA_PIN, sizeof(TFA_PIN), "%s",
             utils_uint8_to_hex(pin_b, TFA_PIN_LEN));
#endif

    // Append PIN to echo
    commander_fill_report(cmd_str(CMD_pin), TFA_PIN, DBB_OK);
    return DBB_OK;
}


static int commander_tfa_check_pin(yajl_val json_node)
{
    const char *pin_path[] = { cmd_str(CMD_sign), cmd_str(CMD_pin), NULL };
    const char *pin = YAJL_GET_STRING(yajl_tree_get(json_node, pin_path, yajl_t_string));

    if (!strlens(pin)) {
        return DBB_ERROR;
    }

    if (!STREQ(pin, TFA_PIN)) {
        return DBB_ERROR;
    }

    return DBB_OK;
}

static uint8_t check_disable_pairing(const char* keypath)
{
    if (keypath == NULL) {
        return 0;
    }
    const char* eth_keypath = "m/44'/60'/";
    const char* etc_keypath = "m/44'/61'/";
    // check if keypath starts with eth_keypath or etc_keypath.
    return !strncmp(keypath, eth_keypath, strlen(eth_keypath)) ||
        !strncmp(keypath, etc_keypath, strlen(etc_keypath));
}

static int commander_echo_command(yajl_val json_node)
{
    const char *meta_path[] = { cmd_str(CMD_sign), cmd_str(CMD_meta), NULL };
    const char *check_path[] = { cmd_str(CMD_sign), cmd_str(CMD_checkpub), NULL };
    const char *data_path[] = { cmd_str(CMD_sign), cmd_str(CMD_data), NULL };

    const char *meta = YAJL_GET_STRING(yajl_tree_get(json_node, meta_path, yajl_t_string));
    yajl_val check = yajl_tree_get(json_node, check_path, yajl_t_array);
    yajl_val data = yajl_tree_get(json_node, data_path, yajl_t_any);
    const char *keypath_path[] = { cmd_str(CMD_keypath), NULL };

    if (meta) {
        commander_fill_report(cmd_str(CMD_meta), meta, DBB_OK);
    }

    if (!YAJL_IS_ARRAY(data) || data->u.array.len == 0) {
        commander_clear_report();
        commander_fill_report(cmd_str(CMD_sign), NULL, DBB_ERR_IO_INVALID_CMD);
        return DBB_ERROR;
    } else {
        memset(json_array, 0, COMMANDER_ARRAY_MAX);
        for (size_t i = 0; i < data->u.array.len; i++) {
            const char *hash_path[] = { cmd_str(CMD_hash), NULL };

            yajl_val obj = data->u.array.values[i];
            const char *keypath = YAJL_GET_STRING(yajl_tree_get(obj, keypath_path, yajl_t_string));
            const char *hash = YAJL_GET_STRING(yajl_tree_get(obj, hash_path, yajl_t_string));

            if (!strlens(hash) || !strlens(keypath)) {
                commander_clear_report();
                commander_fill_report(cmd_str(CMD_sign), NULL, DBB_ERR_IO_INVALID_CMD);
                memset(json_array, 0, COMMANDER_ARRAY_MAX);
                return DBB_ERROR;
            }

            const char *key[] = {cmd_str(CMD_hash), cmd_str(CMD_keypath), 0};
            const char *value[] = {hash, keypath, 0};
            int t[] = {DBB_JSON_STRING, DBB_JSON_STRING, DBB_JSON_NONE};
            commander_fill_json_array(key, value, t, CMD_data);
        }
        commander_fill_report(cmd_str(CMD_data), json_array, DBB_JSON_ARRAY);
    }

    if (check) {
        int ret;
        memset(json_array, 0, COMMANDER_ARRAY_MAX);
        for (size_t i = 0; i < check->u.array.len; i++) {
            const char *pubkey_path[] = { cmd_str(CMD_pubkey), NULL };

            yajl_val obj = check->u.array.values[i];
            const char *keypath = YAJL_GET_STRING(yajl_tree_get(obj, keypath_path, yajl_t_string));
            const char *pubkey = YAJL_GET_STRING(yajl_tree_get(obj, pubkey_path, yajl_t_string));

            if (!strlens(pubkey) || !strlens(keypath)) {
                commander_clear_report();
                commander_fill_report(cmd_str(CMD_sign), NULL, DBB_ERR_IO_INVALID_CMD);
                return DBB_ERROR;
            }

            ret = wallet_check_pubkey(pubkey, keypath);
            const char *status;
            if (ret == DBB_KEY_PRESENT) {
                status = attr_str(ATTR_true);
            } else if (ret == DBB_KEY_ABSENT) {
                status = attr_str(ATTR_false);
            } else {
                return DBB_ERROR;
            }

            const char *key[] = {cmd_str(CMD_pubkey), cmd_str(CMD_present), 0};
            const char *value[] = {pubkey, status, 0};
            int t[] = {DBB_JSON_STRING, DBB_JSON_BOOL, DBB_JSON_NONE};
            commander_fill_json_array(key, value, t, CMD_checkpub);
        }
        commander_fill_report(cmd_str(CMD_checkpub), json_array, DBB_JSON_ARRAY);
    }

    snprintf(json_array, COMMANDER_ARRAY_MAX, "%s", json_report);
    memset(json_report, 0, COMMANDER_REPORT_SIZE);
    commander_fill_report(cmd_str(CMD_sign), json_array, DBB_JSON_ARRAY);

    uint8_t disable_pairing = 1;
    for (size_t i = 0; i < data->u.array.len; i++) {
        const char *keypath = YAJL_GET_STRING(yajl_tree_get(data->u.array.values[i], keypath_path, yajl_t_string));
        if (!check_disable_pairing(keypath)) {
            disable_pairing = 0;
            break;
        }
    }

    if (!disable_pairing && wallet_is_paired()) {
        if (commander_tfa_append_pin() != DBB_OK) {
            return DBB_ERROR;
        }
        int length;
        char *encoded_report = cipher_aes_b64_hmac_encrypt((unsigned char *) json_report,
                                                           strlens(json_report), &length, memory_report_aeskey(TFA_SHARED_SECRET));
        commander_clear_report();
        if (encoded_report) {
            commander_fill_report(cmd_str(CMD_echo), encoded_report, DBB_OK);
        } else {
            commander_fill_report(cmd_str(CMD_echo), NULL, DBB_ERR_MEM_ENCRYPT);
        }
        free(encoded_report);
    } else {
        commander_clear_report();
        commander_fill_report(cmd_str(CMD_echo), "", DBB_OK);
    }

    return DBB_OK;
}


static int commander_touch_button(int found_cmd)
{
    if ((found_cmd == CMD_seed || found_cmd == CMD_reset) && wallet_seeded() != DBB_OK) {
        // Do not require touch if not yet seeded
        return DBB_OK;
    } else if (found_cmd == CMD_bootloader && commander_bootloader_unlocked()) {
        // Do not require touch to relock bootloader
        return DBB_OK;
    } else if (found_cmd < CMD_REQUIRE_TOUCH) {
        return touch_button_press(DBB_TOUCH_LONG);
    } else {
        return DBB_OK;
    }
}


static void commander_access_err(uint8_t err_msg, uint16_t err_count)
{
    char msg[256];
    uint8_t warn_msg = (err_count < COMMANDER_TOUCH_ATTEMPTS) ? DBB_WARN_RESET :
                       DBB_WARN_RESET_TOUCH;
    snprintf(msg, sizeof(msg), "%s %i %s",
             flag_msg(err_msg),
             COMMANDER_MAX_ATTEMPTS - err_count,
             flag_msg(warn_msg));

    commander_fill_report(cmd_str(CMD_input), msg, err_msg);
}


static void commander_parse(char *command)
{
    char *encoded_report;
    int status, cmd, found, found_cmd = 0xFF, encrypt_len;

    // Extract commands
    found = 0;
    yajl_val value, json_node;
    json_node = yajl_tree_parse(command, NULL, 0);
    for (cmd = 0; cmd < CMD_NUM; cmd++) {
        const char *path[] = { cmd_str(cmd), (const char *) 0 };
        value = yajl_tree_get(json_node, path, yajl_t_any);
        if (value) {
            found++;
            found_cmd = cmd;
        }
    }

    // Process commands
    if (!found) {
        commander_fill_report(cmd_str(CMD_input), NULL, DBB_ERR_IO_INVALID_CMD);
    } else if (json_node->u.object.len > 1) {
        commander_fill_report(cmd_str(CMD_input), NULL, DBB_ERR_IO_MULT_CMD);
    } else {
        if (memory_report_access_err_count()) {
            memory_access_err_count(DBB_ACCESS_INITIALIZE);
        }

        // Signing
        if (TFA_VERIFY) {
            TFA_VERIFY = 0;

            if (found_cmd != CMD_sign) {
                memset(TFA_PIN, 0, sizeof(TFA_PIN));
                goto other;
            }

            if (TFA_PIN[0]) {
                if (commander_tfa_check_pin(json_node) != DBB_OK) {
                    commander_access_err(DBB_ERR_SIGN_TFA_PIN, memory_read_pin_err_count() + 1);
                    memory_pin_err_count(DBB_ACCESS_ITERATE);
                    memset(sign_command, 0, COMMANDER_REPORT_SIZE);
                    memset(TFA_PIN, 0, sizeof(TFA_PIN));
                    goto exit;
                } else {
                    memory_pin_err_count(DBB_ACCESS_INITIALIZE);
                    memset(TFA_PIN, 0, sizeof(TFA_PIN));
                }
            }
            status = touch_button_press(DBB_TOUCH_LONG_BLINK);
            if (status == DBB_TOUCHED) {
                yajl_tree_free(json_node);
                json_node = yajl_tree_parse(sign_command, NULL, 0);
                commander_process_sign(json_node);
            } else {
                commander_fill_report(cmd_str(CMD_sign), NULL, status);
            }
            memset(sign_command, 0, COMMANDER_REPORT_SIZE);
            goto exit;
        }

        // Verification 'echo' for signing
        if (found_cmd == CMD_sign) {
            if (commander_echo_command(json_node) == DBB_OK) {
                memset(sign_command, 0, COMMANDER_REPORT_SIZE);
                snprintf(sign_command, COMMANDER_REPORT_SIZE, "%s", command);
                TFA_VERIFY = 1;
            }
            goto exit;
        }

    other:
        // Other commands
        status = commander_touch_button(found_cmd);
        if (status == DBB_TOUCHED || status == DBB_OK) {
            if (commander_process(found_cmd, json_node) == DBB_RESET) {
                yajl_tree_free(json_node);
                return;
            }
        } else {
            commander_fill_report(cmd_str(found_cmd), NULL, status);
        }
    }

exit:
    encoded_report = cipher_aes_b64_hmac_encrypt((unsigned char *)json_report,
                     strlens(json_report), &encrypt_len,
                     memory_active_key_get());

    commander_clear_report();
    if (encoded_report) {
        commander_fill_report(cmd_str(CMD_ciphertext), encoded_report, DBB_OK);
        free(encoded_report);
    } else {
        commander_fill_report(cmd_str(CMD_ciphertext), NULL, DBB_ERR_MEM_ENCRYPT);
    }

    yajl_tree_free(json_node);
}


static uint8_t commander_find_active_key(const char *encrypted_command)
{
    char *cmd_std, *cmd_hdn;
    int len_std = 0, len_hdn = 0;
    uint8_t *key_std, *key_hdn, ret = DBB_ERROR;

    memory_read_aeskeys();
    key_std = memory_report_aeskey(PASSWORD_STAND);
    key_hdn = memory_report_aeskey(PASSWORD_HIDDEN);

    cmd_std = cipher_aes_b64_hmac_decrypt((const unsigned char *)encrypted_command,
                                          strlens(encrypted_command), &len_std, key_std);

    cmd_hdn = cipher_aes_b64_hmac_decrypt((const unsigned char *)encrypted_command,
                                          strlens(encrypted_command), &len_hdn, key_hdn);

    if (strlens(cmd_std)) {
        if (BRACED(cmd_std)) {
            yajl_val json_node = yajl_tree_parse(cmd_std, NULL, 0);
            if (json_node && YAJL_IS_OBJECT(json_node)) {
                if (json_node->u.object.len) {
                    wallet_set_hidden(0);
                    memory_active_key_set(key_std);
                    ret = DBB_OK;
                }
            }
            yajl_tree_free(json_node);
        }
    }
    free(cmd_std);

    if (strlens(cmd_hdn)) {
        if (BRACED(cmd_hdn)) {
            yajl_val json_node = yajl_tree_parse(cmd_hdn, NULL, 0);
            if (json_node && YAJL_IS_OBJECT(json_node)) {
                if (json_node->u.object.len) {
                    wallet_set_hidden(1);
                    memory_active_key_set(key_hdn);
                    ret = DBB_OK;
                }
            }
            yajl_tree_free(json_node);
        }
    }
    free(cmd_hdn);

    return ret;
}


static char *commander_decrypt(const char *encrypted_command)
{
    char *command = NULL;
    int command_len = 0, err = 0;
    uint16_t err_count = 0, err_iter = 0;
    size_t json_object_len = 0;

    if (commander_find_active_key(encrypted_command) == DBB_OK) {
        command = cipher_aes_b64_hmac_decrypt((const unsigned char *)encrypted_command,
                                              strlens(encrypted_command), &command_len,
                                              memory_active_key_get());
    }

    err_count = memory_report_access_err_count();
    err_iter = memory_report_access_err_count() + 1;

    if (strlens(command)) {
        yajl_val json_node = yajl_tree_parse(command, NULL, 0);
        if (json_node && YAJL_IS_OBJECT(json_node)) {
            json_object_len = json_node->u.object.len;
        }
        yajl_tree_free(json_node);
    }

    if (!strlens(command)) {
        err++;
    } else if (!json_object_len) {
        err++;
    } else {
        err_iter--;
    }

    if (!json_object_len || !strlens(command) || err) {
        if (strlens(command)) {
            free(command);
        }

        // Incorrect input
        err_iter = memory_access_err_count(DBB_ACCESS_ITERATE);
        commander_access_err(DBB_ERR_IO_JSON_PARSE, err_iter);
    }

    if (err_iter - err_count == 0 && err == 0) {
        return command;
    }

    if (err_iter - err_count == err) {
        return NULL;
    }

    // Corrupted data
    commander_force_reset();
    return NULL;
}


static int commander_check_init(const char *encrypted_command)
{
    if (memory_report_setup()) {
        commander_fill_report(cmd_str(CMD_input), NULL, DBB_ERR_MEM_SETUP);
        return DBB_ERROR;
    }

    if (!encrypted_command) {
        commander_access_err(DBB_ERR_IO_NO_INPUT, memory_access_err_count(DBB_ACCESS_ITERATE));
        return DBB_ERROR;
    }

    if (!strlens(encrypted_command)) {
        commander_access_err(DBB_ERR_IO_NO_INPUT, memory_access_err_count(DBB_ACCESS_ITERATE));
        return DBB_ERROR;
    }

    // Pong whether or not password is set
    if (BRACED(encrypted_command)) {
        yajl_val json_node = yajl_tree_parse(encrypted_command, NULL, 0);
        if (json_node && YAJL_IS_OBJECT(json_node)) {
            const char *path[] = { cmd_str(CMD_ping), NULL };
            const char *ping = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));
            if (ping) {
                if (memory_report_erased()) {
                    commander_fill_report(cmd_str(CMD_ping), attr_str(ATTR_false), DBB_OK);
                } else {
                    commander_fill_report(cmd_str(CMD_ping), attr_str(ATTR_password), DBB_OK);
                }
                char device_info[100];
                snprintf(device_info, sizeof(device_info),
                        "{\"%s\":\"%s\"}", attr_str(ATTR_version), DIGITAL_BITBOX_VERSION);
                commander_fill_report(cmd_str(CMD_device), device_info, DBB_JSON_OBJECT);
                yajl_tree_free(json_node);
                return DBB_ERROR;
            }
        }
        yajl_tree_free(json_node);
    }

    if (memory_report_access_err_count() >= COMMANDER_TOUCH_ATTEMPTS) {
        if (touch_button_press(DBB_TOUCH_LONG) != DBB_TOUCHED) {
            commander_fill_report(cmd_str(CMD_input), NULL, DBB_ERR_IO_TOUCH_BUTTON);
            return DBB_ERROR;
        }
    }

    // Force setting a password before processing any other command.
    if (!memory_report_erased()) {
        return DBB_OK;
    }

    // An erased wallet should not have seed material present.
    if (wallet_erased() == DBB_ERROR) {
        /* should never enter */
        commander_force_reset();
        return DBB_ERROR;
    }

    if (BRACED(encrypted_command)) {
        yajl_val json_node = yajl_tree_parse(encrypted_command, NULL, 0);
        if (json_node && YAJL_IS_OBJECT(json_node)) {
            const char *path[] = { cmd_str(CMD_password), NULL };
            const char *pw = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));
            if (pw) {
                int ret = commander_process_aes_key(pw, strlens(pw), PASSWORD_STAND);
                if (ret == DBB_OK) {
                    memory_write_erased(0);
                    commander_fill_report(cmd_str(CMD_password), attr_str(ATTR_success), DBB_OK);
                } else {
                    commander_fill_report(cmd_str(CMD_password), NULL, ret);
                }
                yajl_tree_free(json_node);
                return DBB_ERROR;
            }
        }
        yajl_tree_free(json_node);
    }

    commander_fill_report(cmd_str(CMD_input), NULL, DBB_ERR_IO_NO_PASSWORD);
    return DBB_ERROR;
}


//
//  Gateway to the MCU code //
//
char *commander(const char *command)
{
    commander_clear_report();
    if (commander_check_init(command) == DBB_OK) {
        char *command_dec = commander_decrypt(command);
        if (command_dec) {
            commander_parse(command_dec);
            free(command_dec);
        }
    }
    memory_clear();
    return json_report;
}
