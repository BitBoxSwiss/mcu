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
#include <stdlib.h>
#include <stdio.h>

#include "yajl/src/api/yajl_tree.h"
#include "commander.h"
#include "version.h"
#include "random.h"
#include "base64.h"
#include "wallet.h"
#include "utils.h"
#include "flags.h"
#include "aes.h"
#include "led.h"
#ifndef TESTING
#include "ataes132.h"
#include "touch.h"
#include "mcu.h"
#include "sd.h"
#else
#include "sham.h"
#endif


extern const uint8_t MEM_PAGE_ERASE[MEM_PAGE_LEN];

const char *CMD_STR[] = { FOREACH_CMD(GENERATE_STRING) };
const char *ATTR_STR[] = { FOREACH_ATTR(GENERATE_STRING) };

static int REPORT_BUF_OVERFLOW = 0;
__extension__ static char json_report[] = {[0 ... COMMANDER_REPORT_SIZE] = 0};
__extension__ static char json_array[] = {[0 ... COMMANDER_REPORT_SIZE] = 0};
__extension__ static char new_command[] = {[0 ... COMMANDER_REPORT_SIZE] = 0};
__extension__ static char previous_command[] = {[0 ... COMMANDER_REPORT_SIZE] = 0};


// Must free() returned value (allocated inside base64() function)
char *aes_cbc_b64_encrypt(const unsigned char *in, int inlen, int *out_b64len,
                          PASSWORD_ID id)
{
    int  pads;
    int  inpadlen = inlen + N_BLOCK - inlen % N_BLOCK;
    unsigned char inpad[inpadlen];
    unsigned char enc[inpadlen];
    unsigned char iv[N_BLOCK];
    unsigned char enc_cat[inpadlen + N_BLOCK]; // concatenating [ iv0  |  enc ]
    aes_context ctx[1];

    // Set cipher key
    memset(ctx, 0, sizeof(ctx));
    aes_set_key(memory_read_aeskey(id), 32, ctx);

    // PKCS7 padding
    memcpy(inpad, in, inlen);
    for (pads = 0; pads < N_BLOCK - inlen % N_BLOCK; pads++ ) {
        inpad[inlen + pads] = (N_BLOCK - inlen % N_BLOCK);
    }

    // Make a random initialization vector
    if (random_bytes((uint8_t *)iv, N_BLOCK, 0) == STATUS_ERROR) {
        commander_fill_report("random", FLAG_ERR_ATAES, STATUS_ERROR);
        memset(inpad, 0, inpadlen);
        return NULL;
    }
    memcpy(enc_cat, iv, N_BLOCK);

    // CBC encrypt multiple blocks
    aes_cbc_encrypt( inpad, enc, inpadlen / N_BLOCK, iv, ctx );
    memcpy(enc_cat + N_BLOCK, enc, inpadlen);

    // base64 encoding
    int b64len;
    char *b64;
    b64 = base64(enc_cat, inpadlen + N_BLOCK, &b64len);
    *out_b64len = b64len;
    memset(inpad, 0, inpadlen);
    return b64;
}


// Must free() returned value
char *aes_cbc_b64_decrypt(const unsigned char *in, int inlen, int *decrypt_len,
                          PASSWORD_ID id)
{
    *decrypt_len = 0;

    if (!in || inlen == 0) {
        return NULL;
    }

    // Unbase64
    int ub64len;
    unsigned char *ub64 = unbase64((const char *)in, inlen, &ub64len);
    if (!ub64 || (ub64len % N_BLOCK) || ub64len < N_BLOCK) {
        free(ub64);
        return NULL;
    }

    // Set cipher key
    aes_context ctx[1];
    memset(ctx, 0, sizeof(ctx));
    aes_set_key(memory_read_aeskey(id), 32, ctx);

    unsigned char dec_pad[ub64len - N_BLOCK];
    aes_cbc_decrypt(ub64 + N_BLOCK, dec_pad, ub64len / N_BLOCK - 1, ub64, ctx);
    memset(ub64, 0, ub64len);
    free(ub64);

    // Strip PKCS7 padding
    int padlen = dec_pad[ub64len - N_BLOCK - 1];
    if (ub64len - N_BLOCK - padlen <= 0) {
        memset(dec_pad, 0, sizeof(dec_pad));
        return NULL;
    }
    char *dec = malloc(ub64len - N_BLOCK - padlen + 1); // +1 for null termination
    if (!dec) {
        memset(dec_pad, 0, sizeof(dec_pad));
        return NULL;
    }
    memcpy(dec, dec_pad, ub64len - N_BLOCK - padlen);
    dec[ub64len - N_BLOCK - padlen] = '\0';
    *decrypt_len = ub64len - N_BLOCK - padlen + 1;
    memset(dec_pad, 0, sizeof(dec_pad));
    return dec;
}


//
//  Reporting results  //
//

void commander_clear_report(void)
{
    memset(json_report, 0, COMMANDER_REPORT_SIZE);
    REPORT_BUF_OVERFLOW = 0;
}


static void commander_fill_report_len(const char *attr, const char *val, int status,
                                      size_t vallen)
{
    size_t len = strlens(json_report);
    if (len == 0) {
        strncat(json_report, "{", 1);
    } else {
        json_report[len - 1] = ','; // replace closing '}' with continuing ','
    }

    if (COMMANDER_REPORT_SIZE < (vallen + strlens(attr) + len +
                                 (22 < strlens(FLAG_ERR_REPORT_BUFFER) ? strlens(FLAG_ERR_REPORT_BUFFER) : 22))) {
        if (!REPORT_BUF_OVERFLOW) {
            strcat(json_report, FLAG_ERR_REPORT_BUFFER);
            REPORT_BUF_OVERFLOW = 1;
        }
    } else {
        strcat(json_report, " \"");
        strcat(json_report, attr);
        if (status == STATUS_ERROR) {
            strcat(json_report, "\":{ \"error\": ");
        } else {
            strcat(json_report, "\": ");
        }

        if (val[0] == '{' || val[0] == '[') {
            strncat(json_report, val, vallen);
        } else {
            strcat(json_report, "\"");
            strncat(json_report, val, vallen);
            strcat(json_report, "\"");
        }

        // Add closing '}'
        if (status == STATUS_ERROR) {
            strcat(json_report, " } }");
        } else {
            strcat(json_report, " }");
        }
    }
}


void commander_fill_report(const char *attr, const char *val, int status)
{
    commander_fill_report_len(attr, val, status, strlens(val));
}


int commander_fill_json_array(const char **key, const char **value, JSON_TYPE *type,
                              int cmd)
{
    int i = 0;
    char array_element[COMMANDER_ARRAY_ELEMENT_MAX];
    memset(array_element, 0, COMMANDER_ARRAY_ELEMENT_MAX);

    size_t len;

    strcat(array_element, "{");
    while (*key && *value) {
        len = strlens(array_element) + strlens(*key) + strlens(*value) + strlens(", \"\":\"\"}");
        if (len >= COMMANDER_ARRAY_ELEMENT_MAX - 1) {
            commander_clear_report();
            commander_fill_report(CMD_STR[cmd], FLAG_ERR_REPORT_BUFFER, STATUS_ERROR);
            return STATUS_ERROR;
        }
        if (i++ > 0) {
            strcat(array_element, ", ");
        }
        strcat(array_element, "\"");
        strcat(array_element, *key);
        strcat(array_element, "\"");
        strcat(array_element, ":");
        if (type == JSON_TYPE_STRING) {
            strcat(array_element, "\"");
        }
        strcat(array_element, *value);
        if (type == JSON_TYPE_STRING) {
            strcat(array_element, "\"");
        }
        key++;
        value++;
        type++;
    }
    strcat(array_element, "}");

    len = strlens(json_array);
    if (len == 0) {
        strncat(json_array, "[", 1);
    } else {
        json_array[len - 1] = ','; // replace closing ']' with continuing ','
    }
    if (sizeof(json_array) < (strlens(array_element) + len + 3)) {
        commander_clear_report();
        commander_fill_report(CMD_STR[cmd], FLAG_ERR_REPORT_BUFFER, STATUS_ERROR);
        return STATUS_ERROR;
    } else {
        strcat(json_array, array_element);
        strcat(json_array, "]");
        return STATUS_SUCCESS;
    }
}


int commander_fill_signature_array(const uint8_t sig[64], const uint8_t pubkey[33])
{
    char sig_c[128 + 1];
    char pub_key_c[66 + 1];
    strncpy(sig_c, utils_uint8_to_hex(sig, 64), 128 + 1);
    strncpy(pub_key_c, utils_uint8_to_hex(pubkey, 33), 66 + 1);
    const char *key[] = {CMD_STR[CMD_sig_], CMD_STR[CMD_pubkey_], 0};
    const char *value[] = {sig_c, pub_key_c, 0};
    JSON_TYPE type[] = {JSON_TYPE_STRING, JSON_TYPE_STRING, JSON_TYPE_NONE};
    return commander_fill_json_array(key, value, type, CMD_sign_);
}


//
//  Command processing  //
//

void commander_force_reset(void)
{
    memory_erase();
    commander_clear_report();
    commander_fill_report("reset", FLAG_ERR_RESET, STATUS_ERROR);
}


static void commander_process_reset(yajl_val json_node)
{
    const char *path[] = { CMD_STR[CMD_reset_], NULL };
    const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));

    if (!value || !strlens(value)) {
        commander_fill_report("reset", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
    }

    if (strncmp(value, ATTR_STR[ATTR___ERASE___], strlens(ATTR_STR[ATTR___ERASE___])) == 0) {
        if (touch_button_press(0) == STATUS_TOUCHED) {
            delay_ms(100);
            if (touch_button_press(0) == STATUS_TOUCHED) {
                delay_ms(100);
                if (touch_button_press(0) == STATUS_TOUCHED) {
                    memory_erase();
                    commander_clear_report();
                    commander_fill_report("reset", "success", STATUS_SUCCESS);
                }
            }
        }
        return;
    }
}


static void commander_process_name(yajl_val json_node)
{
    const char *path[] = { CMD_STR[CMD_name_], NULL };
    const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));
    commander_fill_report("name", (char *)memory_name(value), STATUS_SUCCESS);
}


static int commander_process_backup_create(const char *filename, const char *encrypt)
{
    char *text, *l;
    int ret;

    if (!filename) {
        commander_fill_report("backup", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
        return STATUS_ERROR;
    }

    text = wallet_mnemonic_from_index(memory_mnemonic(NULL));
    if (!text) {
        commander_fill_report("backup", FLAG_ERR_BIP32_MISSING, STATUS_ERROR);
        return STATUS_ERROR;
    }

    if (encrypt ? !strncmp(encrypt, "yes", 3) : 0) { // default = do not encrypt
        int enc_len;
        char *enc = aes_cbc_b64_encrypt((unsigned char *)text, strlens(text), &enc_len,
                                        PASSWORD_STAND);
        if (!enc) {
            commander_fill_report("backup", FLAG_ERR_ENCRYPT_MEM, STATUS_ERROR);
            free(enc);
            return STATUS_ERROR;
        }
        ret = sd_write(filename, strlens(filename), enc, enc_len, STATUS_SD_NO_REPLACE);
        if (ret != STATUS_SUCCESS) {
            commander_fill_report("backup", FLAG_ERR_SD_WRITE, STATUS_ERROR);
        } else {
            l = sd_load(filename, strlens(filename));
            if (l) {
                if (memcmp(enc, l, enc_len)) {
                    commander_fill_report("backup", FLAG_ERR_SD_FILE_CORRUPT, STATUS_ERROR);
                    ret = STATUS_ERROR;
                }
                memset(l, 0, strlens(l));
            }
        }
        free(enc);
        return ret;
    } else {
        ret = sd_write(filename, strlens(filename), text, strlens(text), STATUS_SD_NO_REPLACE);
        if (ret != STATUS_SUCCESS) {
            commander_fill_report("backup", FLAG_ERR_SD_WRITE, STATUS_ERROR);
        } else {
            l = sd_load(filename, strlens(filename));
            if (l) {
                if (memcmp(text, l, strlens(text))) {
                    commander_fill_report("backup", FLAG_ERR_SD_FILE_CORRUPT, STATUS_ERROR);
                    ret = STATUS_ERROR;
                }
                memset(l, 0, strlens(l));
            }
        }
        return ret;
    }
}


static void commander_process_backup(yajl_val json_node)
{
    const char *encrypt, *filename, *value;

    if (!memory_read_unlocked()) {
        commander_fill_report("backup", FLAG_ERR_DEVICE_LOCKED, STATUS_ERROR);
        return;
    }

    const char *value_path[] = { CMD_STR[CMD_backup_], NULL };
    value = YAJL_GET_STRING(yajl_tree_get(json_node, value_path, yajl_t_string));

    if (value) {
        if (strcmp(value, ATTR_STR[ATTR_list_]) == 0) {
            sd_list();
            return;
        }

        if (strcmp(value, ATTR_STR[ATTR_erase_]) == 0) {
            sd_erase();
            return;
        }
    }

    const char *filename_path[] = { CMD_STR[CMD_backup_], CMD_STR[CMD_filename_], NULL };
    const char *encrypt_path[] = { CMD_STR[CMD_backup_], CMD_STR[CMD_encrypt_], NULL };
    filename = YAJL_GET_STRING(yajl_tree_get(json_node, filename_path, yajl_t_string));
    encrypt = YAJL_GET_STRING(yajl_tree_get(json_node, encrypt_path, yajl_t_string));

    commander_process_backup_create(filename, encrypt);
}


static void commander_process_seed(yajl_val json_node)
{
    int ret;
    char *seed_word[MAX_SEED_WORDS] = {NULL};

    const char *salt_path[] = { CMD_STR[CMD_seed_], CMD_STR[CMD_salt_], NULL };
    const char *source_path[] = { CMD_STR[CMD_seed_], CMD_STR[CMD_source_], NULL };
    const char *decrypt_path[] = { CMD_STR[CMD_seed_], CMD_STR[CMD_decrypt_], NULL };

    const char *salt = YAJL_GET_STRING(yajl_tree_get(json_node, salt_path, yajl_t_string));
    const char *source = YAJL_GET_STRING(yajl_tree_get(json_node, source_path,
                                         yajl_t_string));
    const char *decrypt = YAJL_GET_STRING(yajl_tree_get(json_node, decrypt_path,
                                          yajl_t_string));

    if (!memory_read_unlocked()) {
        commander_fill_report("seed", FLAG_ERR_DEVICE_LOCKED, STATUS_ERROR);
        return;
    }

    if (!source) {
        commander_fill_report("seed", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
        return;
    }

    if (strlens(salt) > SALT_LEN_MAX) {
        commander_fill_report("seed", FLAG_ERR_SALT_LEN, STATUS_ERROR);
        return;
    }

    char *src = malloc(strlens(source) + 1);
    if (!src) {
        commander_fill_report("seed", FLAG_ERR_SEED_MEM, STATUS_ERROR);
        return;
    }
    memcpy(src, source, strlens(source));
    src[strlens(source)] = '\0';

    if (strcmp(src, ATTR_STR[ATTR_create_]) == 0) {

        if (sd_list() != STATUS_SUCCESS) {
            commander_clear_report();
            commander_fill_report("seed", FLAG_ERR_SEED_SD, STATUS_ERROR);
            return;
        }

        char file[strlens(AUTOBACKUP_FILENAME) + 8];
        int count = 1;
        do {
            if (count > AUTOBACKUP_NUM) {
                commander_clear_report();
                commander_fill_report("seed", FLAG_ERR_SEED_SD_NUM, STATUS_ERROR);
                return;
            }
            memset(file, 0, sizeof(file));
            snprintf(file, sizeof(file), "%s%i.aes", AUTOBACKUP_FILENAME, count++);
        } while (sd_load(file, strlens(file)));

        ret = wallet_master_from_mnemonic(NULL, 0, salt, strlens(salt));
        if (ret == STATUS_SUCCESS) {
            if (commander_process_backup_create(file, AUTOBACKUP_ENCRYPT) != STATUS_SUCCESS) {
                memory_erase_seed();
                return;
            }
        }

    } else if (wallet_split_seed(seed_word, src) > 1) {
        ret = wallet_master_from_mnemonic(src, strlens(source), salt, strlens(salt));
    } else {
        char *mnemo = sd_load(src, strlens(source));
        if (mnemo && (decrypt ? !strncmp(decrypt, "yes", 3) : 0)) { // default = do not decrypt
            int dec_len;
            char *dec = aes_cbc_b64_decrypt((unsigned char *)mnemo, strlens(mnemo), &dec_len,
                                            PASSWORD_STAND);
            memset(mnemo, 0, strlens(mnemo));
            memcpy(mnemo, dec, dec_len);
            memset(dec, 0, dec_len);
            free(dec);
        }
        if (mnemo) {
            ret = wallet_master_from_mnemonic(mnemo, strlens(mnemo), salt, strlens(salt));
            memset(mnemo, 0, strlens(mnemo));
        } else {
            ret = STATUS_ERROR;
        }
    }
    memset(src, 0, strlens(source));
    free(src);

    if (ret == STATUS_ERROR) {
        commander_fill_report("seed", FLAG_ERR_MNEMO_CHECK, STATUS_ERROR);
        return;
    }

    if (ret == STATUS_ERROR_MEM) {
        commander_fill_report("seed", FLAG_ERR_ATAES, STATUS_ERROR);
        return;
    }

    commander_clear_report();
    commander_fill_report("seed", "success", STATUS_SUCCESS);
}


static int commander_process_sign_meta(yajl_val json_node)
{
    size_t i;
    int ret;
    const char *data_path[] = { CMD_STR[CMD_sign_], CMD_STR[CMD_data_], NULL };
    yajl_val data = yajl_tree_get(json_node, data_path, yajl_t_array);

    if (!data) {
        commander_fill_report("sign", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
        return STATUS_ERROR;
    }

    memset(json_array, 0, sizeof(json_array));
    for (i = 0; i < data->u.array.len; i++) {
        const char *keypath_path[] = { CMD_STR[CMD_keypath_], NULL };
        const char *hash_path[] = { CMD_STR[CMD_hash_], NULL };

        yajl_val obj = data->u.array.values[i];
        const char *keypath = YAJL_GET_STRING(yajl_tree_get(obj, keypath_path, yajl_t_string));
        const char *hash = YAJL_GET_STRING(yajl_tree_get(obj, hash_path, yajl_t_string));

        if (!hash || !keypath) {
            commander_fill_report("sign", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
            return STATUS_ERROR;
        }

        ret = wallet_sign(hash, strlens(hash), keypath, strlens(keypath), 0);
        if (ret != STATUS_SUCCESS) {
            return ret;
        };
    }
    commander_fill_report("sign", json_array, STATUS_SUCCESS);
    memset(json_array, 0, sizeof(json_array));
    return ret;
}


static int commander_process_sign(yajl_val json_node)
{
    int to_hash = 0;

    const char *type_path[] = { CMD_STR[CMD_sign_], CMD_STR[CMD_type_], NULL };
    const char *data_path[] = { CMD_STR[CMD_sign_], CMD_STR[CMD_data_], NULL };
    const char *keypath_path[] = { CMD_STR[CMD_sign_], CMD_STR[CMD_keypath_], NULL };

    const char *type = YAJL_GET_STRING(yajl_tree_get(json_node, type_path, yajl_t_string));
    const char *data = YAJL_GET_STRING(yajl_tree_get(json_node, data_path, yajl_t_string));
    const char *keypath = YAJL_GET_STRING(yajl_tree_get(json_node, keypath_path,
                                          yajl_t_string));
    if (!type) {
        commander_fill_report("sign", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
        return STATUS_ERROR;
    }

    if (!strncmp(type, ATTR_STR[ATTR_meta_], strlens(ATTR_STR[ATTR_meta_]))) {
        return commander_process_sign_meta(json_node);
    }

    if (!data || !keypath) {
        commander_fill_report("sign", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
        return STATUS_ERROR;
    }

    if (!strncmp(type, ATTR_STR[ATTR_transaction_], strlens(ATTR_STR[ATTR_transaction_]))) {
        to_hash = 1;
    } else if (strncmp(type, ATTR_STR[ATTR_hash_], strlens(ATTR_STR[ATTR_hash_]))) {
        commander_fill_report("sign", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
        return STATUS_ERROR;
    }

    memset(json_array, 0, sizeof(json_array));
    int ret = wallet_sign(data, strlens(data), keypath, strlens(keypath), to_hash);
    commander_fill_report("sign", json_array, STATUS_SUCCESS);
    memset(json_array, 0, sizeof(json_array));
    return ret;
}


static void commander_process_random(yajl_val json_node)
{
    int update_seed;
    uint8_t number[16];

    const char *path[] = { CMD_STR[CMD_random_], NULL };
    const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));

    if (!value || !strlens(value)) {
        commander_fill_report("random", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
    }

    if (strcmp(value, ATTR_STR[ATTR_true_]) == 0) {
        update_seed = 1;
    } else if (strcmp(value, ATTR_STR[ATTR_pseudo_]) == 0) {
        update_seed = 0;
    } else {
        commander_fill_report("random", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
        return;
    }

    if (random_bytes(number, sizeof(number), update_seed) == STATUS_ERROR) {
        commander_fill_report("random", FLAG_ERR_ATAES, STATUS_ERROR);
        return;
    }

    commander_fill_report("random", utils_uint8_to_hex(number, sizeof(number)),
                          STATUS_SUCCESS);
}


static int commander_process_password(const char *message, int msg_len, PASSWORD_ID id)
{
    return (memory_write_aeskey(message, msg_len, id));
}


static void commander_process_verifypass(const char *value)
{
    int ret;
    uint8_t number[16];
    char *l, text[64 + 1];

    if (!memory_read_unlocked()) {
        commander_fill_report("verifypass", FLAG_ERR_DEVICE_LOCKED, STATUS_ERROR);
        return;
    }

    if (!value || !strlens(value)) {
        commander_fill_report("verifypass", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
    }


    if (strcmp(value, ATTR_STR[ATTR_create_]) == 0) {
        if (random_bytes(number, sizeof(number), 1) == STATUS_ERROR) {
            commander_fill_report("random", FLAG_ERR_ATAES, STATUS_ERROR);
            return;
        }
        if (commander_process_password(utils_uint8_to_hex(number, sizeof(number)),
                                       sizeof(number) * 2, PASSWORD_VERIFY) != STATUS_SUCCESS) {
            return;
        }
        commander_fill_report(ATTR_STR[ATTR_create_], "success", STATUS_SUCCESS);

    } else if (strcmp(value, ATTR_STR[ATTR_export_]) == 0) {
        memcpy(text, utils_uint8_to_hex(memory_read_aeskey(PASSWORD_VERIFY), 32), 64 + 1);
        utils_clear_buffers();
        ret = sd_write(VERIFYPASS_FILENAME, sizeof(VERIFYPASS_FILENAME), text, 64 + 1,
                       STATUS_SD_REPLACE);
        if (ret != STATUS_SUCCESS) {
            commander_fill_report(ATTR_STR[ATTR_export_], FLAG_ERR_SD_WRITE, STATUS_ERROR);
            memset(text, 0, sizeof(text));
            return;
        }
        l = sd_load(VERIFYPASS_FILENAME, sizeof(VERIFYPASS_FILENAME));
        if (!l) {
            commander_fill_report(ATTR_STR[ATTR_export_], FLAG_ERR_SD_FILE_CORRUPT, STATUS_ERROR);
            memset(text, 0, sizeof(text));
            return;
        }
        if (memcmp(text, l, strlens(text))) {
            commander_fill_report(ATTR_STR[ATTR_export_], FLAG_ERR_SD_FILE_CORRUPT, STATUS_ERROR);
        } else {
            commander_fill_report(ATTR_STR[ATTR_export_], "success", STATUS_SUCCESS);
        }
        memset(l, 0, strlens(l));
        memset(text, 0, sizeof(text));
    } else {
        commander_fill_report("verifypass", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
    }
}


void commander_create_verifypass(void)
{
    commander_process_verifypass(ATTR_STR[ATTR_create_]);
}


static void commander_process_xpub(yajl_val json_node)
{
    char xpub[112] = {0};
    const char *path[] = { CMD_STR[CMD_xpub_], NULL };
    const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));

    if (!value || !strlens(value)) {
        commander_fill_report("xpub", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
        return;
    }

    wallet_report_xpub(value, strlens(value), xpub);

    if (xpub[0]) {
        commander_fill_report("xpub", xpub, STATUS_SUCCESS);

        int encrypt_len;
        char *encoded_report;
        encoded_report = aes_cbc_b64_encrypt((unsigned char *)xpub,
                                             strlens(xpub),
                                             &encrypt_len,
                                             PASSWORD_VERIFY);
        commander_fill_report_len("echo", encoded_report, STATUS_SUCCESS, encrypt_len);
    } else {
        commander_fill_report("xpub", FLAG_ERR_XPUB, STATUS_ERROR);
    }
}


static void commander_process_device(yajl_val json_node)
{
    const char *path[] = { CMD_STR[CMD_device_], NULL };
    const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));

    if (!value || !strlens(value)) {
        commander_fill_report("device", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
    }

    if (strcmp(value, ATTR_STR[ATTR_serial_]) == 0) {
        uint32_t serial[4] = {0};
        if (!flash_read_unique_id(serial, 4)) {
            commander_fill_report(ATTR_STR[ATTR_serial_], utils_uint8_to_hex((uint8_t *)serial,
                                  sizeof(serial)), STATUS_SUCCESS);
        } else {
            commander_fill_report(ATTR_STR[ATTR_serial_], FLAG_ERR_FLASH, STATUS_ERROR);
        }
        return;
    }

    if (strcmp(value, ATTR_STR[ATTR_version_]) == 0) {
        commander_fill_report(ATTR_STR[ATTR_version_], (const char *)DIGITAL_BITBOX_VERSION,
                              STATUS_SUCCESS);
        return;
    }

    if (strcmp(value, ATTR_STR[ATTR_lock_]) == 0) {
        memory_write_unlocked(0);
        commander_fill_report("device", "locked", STATUS_SUCCESS);
        return;
    }

    commander_fill_report("device", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
}


static void commander_process_aes256cbc(yajl_val json_node)
{
    const char *type, *data;
    char *crypt;
    int crypt_len;

    const char *type_path[] = { CMD_STR[CMD_aes256cbc_], CMD_STR[CMD_type_], NULL };
    const char *data_path[] = { CMD_STR[CMD_aes256cbc_], CMD_STR[CMD_data_], NULL };
    type = YAJL_GET_STRING(yajl_tree_get(json_node, type_path, yajl_t_string));
    data = YAJL_GET_STRING(yajl_tree_get(json_node, data_path, yajl_t_string));

    if (!type || !data) {
        commander_fill_report("aes256cbc", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
        return;
    }

    if (strncmp(type, ATTR_STR[ATTR_password_], strlens(ATTR_STR[ATTR_password_])) == 0) {
        if (commander_process_password(data, strlens(data), PASSWORD_CRYPT) == STATUS_SUCCESS) {
            commander_fill_report("aes256cbc", "success", STATUS_SUCCESS);
        }
    } else if (strncmp(type, ATTR_STR[ATTR_xpub_], strlens(ATTR_STR[ATTR_xpub_])) == 0) {
        char xpub[112] = {0};
        wallet_report_xpub(data, strlens(data), xpub);
        if (xpub[0]) {
            if (commander_process_password(xpub, 112, PASSWORD_CRYPT) == STATUS_SUCCESS) {
                commander_fill_report("aes256cbc", "success", STATUS_SUCCESS);
            }
        } else {
            commander_fill_report("aes256cbc", FLAG_ERR_BIP32_MISSING, STATUS_ERROR);
        }
    } else if (memory_aeskey_is_erased(PASSWORD_CRYPT) == STATUS_MEM_ERASED) {
        commander_fill_report("aes256cbc", FLAG_ERR_NO_PASSWORD, STATUS_ERROR);
    } else if (strncmp(type, ATTR_STR[ATTR_encrypt_],
                       strlens(ATTR_STR[ATTR_encrypt_])) == 0) {
        if (strlens(data) > DATA_LEN_MAX) {
            commander_fill_report("aes256cbc", FLAG_ERR_DATA_LEN, STATUS_ERROR);
        } else {
            crypt = aes_cbc_b64_encrypt((const unsigned char *)data, strlens(data), &crypt_len,
                                        PASSWORD_CRYPT);
            if (crypt) {
                commander_fill_report_len("aes256cbc", crypt, STATUS_SUCCESS, crypt_len);
            } else {
                commander_fill_report("aes256cbc", FLAG_ERR_ENCRYPT_MEM, STATUS_ERROR);
            }
            free(crypt);
        }
    } else if (strncmp(type, ATTR_STR[ATTR_decrypt_],
                       strlens(ATTR_STR[ATTR_decrypt_])) == 0) {
        crypt = aes_cbc_b64_decrypt((const unsigned char *)data, strlens(data), &crypt_len,
                                    PASSWORD_CRYPT);
        if (crypt) {
            commander_fill_report_len("aes256cbc", crypt, STATUS_SUCCESS, crypt_len);
        } else {
            commander_fill_report("aes256cbc", FLAG_ERR_DECRYPT, STATUS_ERROR);
        }
        free(crypt);
    } else {
        commander_fill_report("aes256cbc", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
    }
}


static void commander_process_led(yajl_val json_node)
{
    const char *path[] = { CMD_STR[CMD_led_], NULL };
    const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));

    if (!value || !strlens(value)) {
        commander_fill_report("led", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
    }

    if (strncmp(value, ATTR_STR[ATTR_toggle_],
                strlens(ATTR_STR[ATTR_toggle_])) != 0) {
        commander_fill_report("led", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
    } else {
        led_toggle();
        delay_ms(300);
        led_toggle();
        commander_fill_report("led", "toggled", STATUS_SUCCESS);
    }
}


static int commander_process(int cmd, yajl_val json_node)
{
    switch (cmd) {
        case CMD_reset_:
            commander_process_reset(json_node);
            return STATUS_RESET;

        case CMD_password_: {
            const char *path[] = { CMD_STR[CMD_password_], NULL };
            const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));
            if (commander_process_password(value, strlens(value), PASSWORD_STAND) == STATUS_SUCCESS) {
                commander_fill_report(CMD_STR[cmd], "success", STATUS_SUCCESS);
            }
            break;
        }

        case CMD_verifypass_: {
            const char *path[] = { CMD_STR[CMD_verifypass_], NULL };
            const char *value = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));
            commander_process_verifypass(value);
            break;
        }

        case CMD_led_:
            commander_process_led(json_node);
            break;

        case CMD_name_:
            commander_process_name(json_node);
            break;

        case CMD_seed_:
            commander_process_seed(json_node);
            break;

        case CMD_backup_:
            commander_process_backup(json_node);
            break;

        case CMD_sign_:
            return commander_process_sign(json_node);

        case CMD_random_:
            commander_process_random(json_node);
            break;

        case CMD_xpub_:
            commander_process_xpub(json_node);
            break;

        case CMD_device_:
            commander_process_device(json_node);
            break;

        case CMD_aes256cbc_:
            commander_process_aes256cbc(json_node);
            break;

        default:
            commander_fill_report("input", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
            return STATUS_ERROR;
    }
    return STATUS_SUCCESS;
}


//
//  Unit testing
//

int commander_test_static_functions(void)
{
    // test json_report overflows
    __extension__ char val[] = { [0 ... COMMANDER_REPORT_SIZE] = '1' };
    commander_clear_report();
    commander_fill_report_len("testing", val, STATUS_SUCCESS, COMMANDER_REPORT_SIZE / 2);
    commander_fill_report_len("testing", val, STATUS_SUCCESS, COMMANDER_REPORT_SIZE / 2);
    if (!strstr(json_report, FLAG_ERR_REPORT_BUFFER)) {
        goto err;
    }

    uint8_t sig[64] = {0};
    uint8_t pubkey[33] = {0};
    commander_clear_report();
    commander_fill_report_len("testing", val, STATUS_SUCCESS,
                              COMMANDER_REPORT_SIZE - sizeof(sig) - sizeof(pubkey) - strlens(FLAG_ERR_REPORT_BUFFER));
    commander_fill_signature_array(sig, pubkey);
    commander_fill_report("sign", json_array, STATUS_SUCCESS);
    if (!strstr(json_report, FLAG_ERR_REPORT_BUFFER)) {
        goto err;
    }

    return 0;
err:
    return 1;
}


//
//  Handle API input (preprocessing) //
//

static int commander_append_pin(void)
{
    if (!memory_read_unlocked()) {
        // Create one-time PIN
        uint8_t pin_b[2];
        char pin_c[5];
        if (random_bytes(pin_b, 2, 0) == STATUS_ERROR) {
            commander_fill_report("random", FLAG_ERR_ATAES, STATUS_ERROR);
            return STATUS_ERROR;
        }
        sprintf(pin_c, "%04d", (pin_b[1] * 256 + pin_b[0]) % 10000); // 0 to 9999

        // Create 2FA AES key
        commander_process_password(pin_c, 4, PASSWORD_2FA);

        // Append PIN to echo
        commander_fill_report(CMD_STR[CMD_pin_], pin_c, STATUS_SUCCESS);
    }
    return STATUS_SUCCESS;
}


static int commander_echo_command(yajl_val json_node)
{
    const char *type_path[] = { CMD_STR[CMD_sign_], CMD_STR[CMD_type_], NULL };
    const char *meta_path[] = { CMD_STR[CMD_sign_], CMD_STR[CMD_meta_], NULL };
    const char *change_keypath_path[] = { CMD_STR[CMD_sign_], CMD_STR[CMD_changekeypath_], NULL };
    const char *check_path[] = { CMD_STR[CMD_sign_], CMD_STR[CMD_checkpub_], NULL };
    const char *data_path[] = { CMD_STR[CMD_sign_], CMD_STR[CMD_data_], NULL };

    const char *type = YAJL_GET_STRING(yajl_tree_get(json_node, type_path, yajl_t_string));
    const char *meta = YAJL_GET_STRING(yajl_tree_get(json_node, meta_path, yajl_t_string));
    const char *change_keypath = YAJL_GET_STRING(yajl_tree_get(json_node, change_keypath_path,
                                 yajl_t_string));
    yajl_val check = yajl_tree_get(json_node, check_path, yajl_t_array);
    yajl_val data = yajl_tree_get(json_node, data_path, yajl_t_any);



    if (!type) {
        commander_fill_report(CMD_STR[CMD_sign_], FLAG_ERR_INVALID_CMD, STATUS_ERROR);
        return STATUS_ERROR;
    }


    if (!strncmp(type, ATTR_STR[ATTR_meta_], strlens(ATTR_STR[ATTR_meta_]))) {
        // Type: meta

        if (!memcmp(previous_command, new_command, COMMANDER_REPORT_SIZE)) {
            return STATUS_VERIFY_SAME;
        }
        memset(previous_command, 0, COMMANDER_REPORT_SIZE);
        memcpy(previous_command, new_command, COMMANDER_REPORT_SIZE);
        commander_clear_report();

        if (meta) {
            commander_fill_report(CMD_STR[CMD_meta_], meta, STATUS_SUCCESS);
        }

        if (!YAJL_IS_ARRAY(data)) {
            commander_clear_report();
            commander_fill_report(CMD_STR[CMD_sign_], FLAG_ERR_INVALID_CMD, STATUS_ERROR);
            return STATUS_ERROR;
        } else {
            memset(json_array, 0, sizeof(json_array));
            for (size_t i = 0; i < data->u.array.len; i++) {
                const char *keypath_path[] = { CMD_STR[CMD_keypath_], NULL };
                const char *hash_path[] = { CMD_STR[CMD_hash_], NULL };

                yajl_val obj = data->u.array.values[i];
                const char *keypath = YAJL_GET_STRING(yajl_tree_get(obj, keypath_path, yajl_t_string));
                const char *hash = YAJL_GET_STRING(yajl_tree_get(obj, hash_path, yajl_t_string));

                if (!hash || !keypath) {
                    commander_clear_report();
                    commander_fill_report(CMD_STR[CMD_sign_], FLAG_ERR_INVALID_CMD, STATUS_ERROR);
                    memset(json_array, 0, sizeof(json_array));
                    return STATUS_ERROR;
                }

                const char *key[] = {CMD_STR[CMD_hash_], CMD_STR[CMD_keypath_], 0};
                const char *value[] = {hash, keypath, 0};
                JSON_TYPE t[] = {JSON_TYPE_STRING, JSON_TYPE_STRING, JSON_TYPE_NONE};
                commander_fill_json_array(key, value, t, CMD_data_);
            }
            commander_fill_report(CMD_STR[CMD_data_], json_array, STATUS_SUCCESS);
        }

        if (check) {
            int ret;
            memset(json_array, 0, sizeof(json_array));
            for (size_t i = 0; i < check->u.array.len; i++) {
                const char *keypath_path[] = { CMD_STR[CMD_keypath_], NULL };
                const char *address_path[] = { CMD_STR[CMD_address_], NULL };

                yajl_val obj = check->u.array.values[i];
                const char *keypath = YAJL_GET_STRING(yajl_tree_get(obj, keypath_path, yajl_t_string));
                const char *address = YAJL_GET_STRING(yajl_tree_get(obj, address_path, yajl_t_string));

                if (!address || !keypath) {
                    commander_clear_report();
                    commander_fill_report(CMD_STR[CMD_checkpub_], FLAG_ERR_INVALID_CMD, STATUS_ERROR);
                    return STATUS_ERROR;
                }

                ret = wallet_check_pubkey(address, keypath, strlens(keypath));
                const char *status;
                if (ret == STATUS_KEY_PRESENT) {
                    status = "true";
                } else if (ret == STATUS_KEY_ABSENT) {
                    status = "false";
                } else {
                    return STATUS_ERROR;
                }

                const char *key[] = {CMD_STR[CMD_address_], CMD_STR[CMD_present_], 0};
                const char *value[] = {address, status, 0};
                JSON_TYPE t[] = {JSON_TYPE_STRING, JSON_TYPE_BOOL, JSON_TYPE_NONE};
                commander_fill_json_array(key, value, t, CMD_checkpub_);
            }
            commander_fill_report(CMD_STR[CMD_checkpub_], json_array, STATUS_SUCCESS);
        }

        memcpy(json_array, json_report, COMMANDER_REPORT_SIZE);
        memset(json_report, 0, COMMANDER_REPORT_SIZE);
        commander_fill_report(CMD_STR[CMD_sign_], json_array, STATUS_SUCCESS);


    } else if (!strncmp(type, ATTR_STR[ATTR_transaction_],
                        strlens(ATTR_STR[ATTR_transaction_]))) {
        // Type: transaction

        const char *data_str = YAJL_GET_STRING(data);

        if (!data_str) {
            commander_fill_report(CMD_STR[CMD_sign_], FLAG_ERR_INVALID_CMD, STATUS_ERROR);
            return STATUS_ERROR;
        }

        char outputs[strlens(data_str)];
        if (wallet_get_outputs(data_str, strlens(data_str), outputs,
                               sizeof(outputs)) != STATUS_SUCCESS) {
            return STATUS_ERROR;
        }

        // Deserialize and check if a change address is present (when more than one output is given).
        memset(json_array, 0, sizeof(json_array));
        if (wallet_deserialize_output(outputs, change_keypath,
                                      strlens(change_keypath)) != STATUS_SUCCESS) {
            commander_fill_report(CMD_STR[CMD_sign_], FLAG_ERR_DESERIALIZE, STATUS_ERROR);
            return STATUS_ERROR;
        }

        if (!memcmp(previous_command, outputs, strlens(outputs))) {
            return STATUS_VERIFY_SAME;
        }
        memset(previous_command, 0, COMMANDER_REPORT_SIZE);
        memcpy(previous_command, outputs, strlens(outputs));

        commander_clear_report();
        commander_fill_report(CMD_STR[CMD_verify_output_], json_array, STATUS_SUCCESS);


    } else if (!strncmp(type, ATTR_STR[ATTR_hash_], strlens(ATTR_STR[ATTR_hash_]))) {
        // Type: hash

        if (!memcmp(previous_command, new_command, COMMANDER_REPORT_SIZE)) {
            return STATUS_VERIFY_SAME;
        }
        memset(previous_command, 0, COMMANDER_REPORT_SIZE);
        memcpy(previous_command, new_command, COMMANDER_REPORT_SIZE);

        // Echo entire command
        commander_clear_report();
        memcpy(json_report, new_command, strlens(new_command));


    } else {
        commander_fill_report(CMD_STR[CMD_sign_], FLAG_ERR_INVALID_CMD, STATUS_ERROR);
        return STATUS_ERROR;
    }


    if (commander_append_pin() != STATUS_SUCCESS) {
        return STATUS_ERROR;
    }

    int encrypt_len;
    char *encoded_report;
    encoded_report = aes_cbc_b64_encrypt((unsigned char *)json_report,
                                         strlens(json_report),
                                         &encrypt_len,
                                         PASSWORD_VERIFY);
    commander_clear_report();
    if (encoded_report) {
        commander_fill_report_len("echo", encoded_report, STATUS_SUCCESS, encrypt_len);
    } else {
        commander_fill_report("echo", FLAG_ERR_ENCRYPT_MEM, STATUS_ERROR);
    }
    free(encoded_report);

    return STATUS_VERIFY_DIFFERENT;
}


static int commander_touch_button(int found_cmd, yajl_val json_node)
{
    if (found_cmd == CMD_sign_) {
        int c = commander_echo_command(json_node);
        if (c == STATUS_VERIFY_SAME) {
            int t;
            t = touch_button_press(1);
            if (t != STATUS_TOUCHED) {
                // Clear previous signing information
                // to force touch for next sign command.
                memset(previous_command, 0, COMMANDER_REPORT_SIZE);
            }
            return (t);
        } else if (c == STATUS_VERIFY_DIFFERENT) {
            return STATUS_VERIFY_ECHO;
        } else {
            memset(previous_command, 0, COMMANDER_REPORT_SIZE);
            return STATUS_ERROR;
        }
    }

    // Reset if not sign command
    memset(previous_command, 0, COMMANDER_REPORT_SIZE);

    if (found_cmd == CMD_seed_ && !memcmp(memory_master(NULL), MEM_PAGE_ERASE, 32)) {
        return STATUS_TOUCHED;
    } else if (found_cmd < CMD_require_touch_) {
        return (touch_button_press(0));

    } else {
        return STATUS_TOUCHED;
    }
}


static void commander_parse(char *command)
{
    char *encoded_report;
    int t, cmd, ret, err, found, found_cmd = 0xFF, encrypt_len;

    memset(new_command, 0, COMMANDER_REPORT_SIZE);
    snprintf(new_command, COMMANDER_REPORT_SIZE, "%s", command);

    // Extract commands
    err = 0;
    found = 0;
    yajl_val value, json_node = yajl_tree_parse(command, NULL, 0);
    for (cmd = 0; cmd < CMD_NUM; cmd++) {
        const char *path[] = { CMD_STR[cmd], (const char *) 0 };
        value = yajl_tree_get(json_node, path, yajl_t_any);
        if (value) {
            found++;
            found_cmd = cmd;
        }
    }


    // Process commands
    if (!found) {
        commander_fill_report("input", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
    } else if (json_node->u.object.len > 1) {
        commander_fill_report("input", FLAG_ERR_MULTIPLE_CMD, STATUS_ERROR);
    } else {
        memory_access_err_count(STATUS_ACCESS_INITIALIZE);
        t = commander_touch_button(found_cmd, json_node);


        if (t == STATUS_VERIFY_ECHO) {
            goto exit;
        } else if (t == STATUS_TOUCHED) {
            ret = commander_process(found_cmd, json_node);
            if (ret == STATUS_RESET) {
                goto exit;
            } else if (ret == STATUS_ERROR) {
                err++;
            }
        } else {
            // error or not touched
            err++;
        }

        if (found_cmd == CMD_sign_ && !memory_read_unlocked() && !err) {
            encoded_report = aes_cbc_b64_encrypt((unsigned char *)json_report,
                                                 strlens(json_report),
                                                 &encrypt_len,
                                                 PASSWORD_2FA);
            commander_clear_report();
            if (encoded_report) {
                commander_fill_report_len("2FA", encoded_report, STATUS_SUCCESS, encrypt_len);
                free(encoded_report);
            } else {
                commander_fill_report("2FA", FLAG_ERR_ENCRYPT_MEM, STATUS_ERROR);
            }
        }
    }

    encoded_report = aes_cbc_b64_encrypt((unsigned char *)json_report,
                                         strlens(json_report),
                                         &encrypt_len,
                                         PASSWORD_STAND);
    commander_clear_report();

    if (encoded_report) {
        commander_fill_report_len("ciphertext", encoded_report, STATUS_SUCCESS, encrypt_len);
    } else {
        commander_fill_report("output", FLAG_ERR_ENCRYPT_MEM, STATUS_ERROR);
    }
    free(encoded_report);

exit:
    yajl_tree_free(json_node);
}


static char *commander_decrypt(const char *encrypted_command)
{
    char *command;
    int command_len = 0, err = 0;
    uint16_t err_count = 0, err_iter = 0;
    size_t json_object_len = 0;


    command = aes_cbc_b64_decrypt((const unsigned char *)encrypted_command,
                                  strlens(encrypted_command),
                                  &command_len,
                                  PASSWORD_STAND);

    err_count = memory_read_access_err_count(); // Reads over TWI introduce additional
    err_iter = memory_read_access_err_count();  // temporal jitter in code execution.

    if (command == NULL) {
        err++;
        commander_fill_report("input", FLAG_ERR_DECRYPT " "
                              FLAG_ERR_RESET_WARNING, STATUS_ERROR);
        err_iter = memory_access_err_count(STATUS_ACCESS_ITERATE);
    } else {
        yajl_val json_node = yajl_tree_parse(command, NULL, 0);
        if (json_node && YAJL_IS_OBJECT(json_node)) {
            json_object_len = json_node->u.object.len;
        }
        yajl_tree_free(json_node);
    }

    if (!json_object_len && err == 0) {
        err++;
        commander_fill_report("input", FLAG_ERR_JSON_PARSE " "
                              FLAG_ERR_RESET_WARNING " "
                              FLAG_ERR_JSON_BRACKET, STATUS_ERROR);
        err_iter = memory_access_err_count(STATUS_ACCESS_ITERATE);
    }

    if (err_iter - err_count == 0 && err == 0) {
        return command;
    }

    free(command);
    if (err_iter - err_count == err) {
        return NULL;
    }

    // Corrupted data
    commander_force_reset();
    return NULL;
}


static int commander_check_init(const char *encrypted_command)
{
    int ret;

    if (!encrypted_command) {
        commander_fill_report("input", FLAG_ERR_NO_INPUT " "
                              FLAG_ERR_RESET_WARNING, STATUS_ERROR);
        memory_access_err_count(STATUS_ACCESS_ITERATE);
        ret = STATUS_ERROR;
        goto exit;
    }

    if (!strlens(encrypted_command)) {
        commander_fill_report("input", FLAG_ERR_NO_INPUT " "
                              FLAG_ERR_RESET_WARNING, STATUS_ERROR);
        memory_access_err_count(STATUS_ACCESS_ITERATE);
        ret = STATUS_ERROR;
        goto exit;
    }

    yajl_val json_node = yajl_tree_parse(encrypted_command, NULL, 0);

    // In case of a forgotten password, allow reset from an unencrypted command.
    if (json_node && YAJL_IS_OBJECT(json_node)) {
        const char *path[] = { CMD_STR[CMD_reset_], NULL };
        if (yajl_tree_get(json_node, path, yajl_t_string)) {
            commander_process_reset(json_node);
            ret = STATUS_RESET;
            goto exit_free;
        }
    }

    // Force setting a password for encryption before processing command.
    if (!memory_read_erased()) {
        ret = STATUS_SUCCESS;
        goto exit_free;
    }

    ret = STATUS_ERROR;
    if (json_node && YAJL_IS_OBJECT(json_node)) {
        const char *path[] = { CMD_STR[CMD_password_], NULL };
        const char *pw = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));
        if (pw) {
            if (commander_process_password(pw, strlens(pw), PASSWORD_STAND) == STATUS_SUCCESS) {
                memory_write_erased(0);
                commander_fill_report(CMD_STR[CMD_password_], "success", STATUS_SUCCESS);
            } else {
                commander_fill_report("input", FLAG_ERR_INVALID_CMD, STATUS_ERROR);
            }
            goto exit_free;
        }
    }
    commander_fill_report("input", FLAG_ERR_NO_PASSWORD, STATUS_ERROR);

exit_free:
    yajl_tree_free(json_node);
exit:
    return ret;

}


//
//  Gateway to the MCU code //
//
char *commander(const char *command)
{
    commander_clear_report();
    if (commander_check_init(command) == STATUS_SUCCESS) {
        char *command_dec = commander_decrypt(command);
        if (command_dec) {
            commander_parse(command_dec);
            free(command_dec);
        }
    }

    memory_clear_variables();
    return json_report;
}


/*
 *

 USB HID INPUT
 |
 |
commander()
 |
 \_commander_check_init()
    |--if 'reset' command -> RESET -> RETURN
    |--if password not set -> RETURN
    |
 \_commander_decrypt()
    |--if cannot decrypt input (serves as a password check) or cannot parse JSON
    |      |-> if too many access errors -> RESET
    |      |-> RETURN
    |
    |
 \_commander_parse()
    |
    \_commander_touch_button()
            |--if sign command
            |      |--if new transaction -> echo 2FA info -> RETURN
            |      |--if repeated, wait for user input (touch button)
            |
            |--if require touch & not touched -> RETURN
            |
    \_commander_process() { do command }
            |
      _____/
    |
    |--encrypt output report
  _/
 |
 |
 USB HID OUTPUT

*
*/
