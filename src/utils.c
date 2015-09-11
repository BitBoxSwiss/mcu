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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "utils.h"
#include "flags.h"
#include "commander.h"
#include "yajl/src/api/yajl_tree.h"

extern const char *CMD_STR[];
static char PIN_2FA[5] = {0};
static char decrypted_report[COMMANDER_REPORT_SIZE];
static uint8_t buffer_hex_to_uint8[TO_UINT8_HEX_BUF_LEN];
static char buffer_uint8_to_hex[TO_UINT8_HEX_BUF_LEN];


void utils_clear_buffers(void)
{
    memset(buffer_hex_to_uint8, 0, TO_UINT8_HEX_BUF_LEN);
    memset(buffer_uint8_to_hex, 0, TO_UINT8_HEX_BUF_LEN);
}


uint8_t *utils_hex_to_uint8(const char *str)
{
    if (strlens(str) > TO_UINT8_HEX_BUF_LEN) {
        return NULL;
    }
    memset(buffer_hex_to_uint8, 0, TO_UINT8_HEX_BUF_LEN);
    uint8_t c;
    size_t i;
    for (i = 0; i < strlens(str) / 2; i++) {
        c = 0;
        if (str[i * 2] >= '0' && str[i * 2] <= '9') {
            c += (str[i * 2] - '0') << 4;
        }
        if (str[i * 2] >= 'a' && str[i * 2] <= 'f') {
            c += (10 + str[i  * 2] - 'a') << 4;
        }
        if (str[i * 2] >= 'A' && str[i * 2] <= 'F') {
            c += (10 + str[i * 2] - 'A') << 4;
        }
        if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') {
            c += (str[i * 2 + 1] - '0');
        }
        if (str[i * 2 + 1] >= 'a' && str[i * 2 + 1] <= 'f') {
            c += (10 + str[i * 2 + 1] - 'a');
        }
        if (str[i * 2 + 1] >= 'A' && str[i * 2 + 1] <= 'F') {
            c += (10 + str[i * 2 + 1] - 'A');
        }
        buffer_hex_to_uint8[i] = c;
    }
    return buffer_hex_to_uint8;
}


char *utils_uint8_to_hex(const uint8_t *bin, size_t l)
{
    if (l > (TO_UINT8_HEX_BUF_LEN / 2 - 1)) {
        return NULL;
    }
    static char digits[] = "0123456789abcdef";
    memset(buffer_uint8_to_hex, 0, TO_UINT8_HEX_BUF_LEN);
    size_t i;
    for (i = 0; i < l; i++) {
        buffer_uint8_to_hex[i * 2] = digits[(bin[i] >> 4) & 0xF];
        buffer_uint8_to_hex[i * 2 + 1] = digits[bin[i] & 0xF];
    }
    buffer_uint8_to_hex[l * 2] = '\0';
    return buffer_uint8_to_hex;
}


void utils_reverse_hex(char *h, int len)
{
    char copy[len];
    strncpy(copy, h, len);
    int i;
    for (i = 0; i < len; i += 2) {
        h[i] = copy[len - i - 2];
        h[i + 1] = copy[len - i - 1];
    }
}


void utils_uint64_to_varint(char *vi, int *l, uint64_t i)
{
    int len;
    char v[VARINT_LEN];

    if (i < 0xfd) {
        sprintf(v, "%02" PRIx64 , i);
        len = 2;
    } else if (i <= 0xffff) {
        sprintf(v, "%04" PRIx64 , i);
        sprintf(vi, "fd");
        len = 4;
    } else if (i <= 0xffffffff) {
        sprintf(v, "%08" PRIx64 , i);
        sprintf(vi, "fe");
        len = 8;
    } else {
        sprintf(v, "%016" PRIx64 , i);
        sprintf(vi, "ff");
        len = 16;
    }

    // reverse order
    if (len > 2) {
        utils_reverse_hex(v, len);
        strncat(vi, v, len);
    } else {
        strncpy(vi, v, len);
    }

    *l = len;
}


int utils_varint_to_uint64(const char *vi, uint64_t *i)
{
    char v[VARINT_LEN] = {0};
    int len;

    if (!vi) {
        len = 0;
    } else if (!strncmp(vi, "ff", 2)) {
        len = 16;
    } else if (!strncmp(vi, "fe", 2)) {
        len = 8;
    } else if (!strncmp(vi, "fd", 2)) {
        len = 4;
    } else {
        len = 2;
    }

    if (len == 0) {
        // continue
    } else if (len > 2) {
        strncpy(v, vi + 2, len);
        utils_reverse_hex(v, len);
    } else {
        strncpy(v, vi, len);
    }
    *i = strtoull(v, NULL, 16);

    return len;
}


char *utils_read_decrypted_report(void)
{
    return decrypted_report;
}


void utils_decrypt_report(const char *report)
{
    int decrypt_len, dec_tfa_len;
    char *dec, *dec_tfa;
    const char *pin, *tfa;

    memset(decrypted_report, 0, sizeof(decrypted_report));

    yajl_val json_node = yajl_tree_parse(report, NULL, 0);

    if (!json_node) {
        strcpy(decrypted_report, "/* error: Failed to parse report. */");
        return;
    }

    size_t i, r = json_node->u.object.len;
    for (i = 0; i < r; i++) {
        const char *ciphertext_path[] = { CMD_STR[CMD_ciphertext_], (const char *) 0 };
        const char *echo_path[] = { "echo", (const char *) 0 };
        const char *ciphertext = YAJL_GET_STRING(yajl_tree_get(json_node, ciphertext_path,
                                 yajl_t_string));
        const char *echo = YAJL_GET_STRING(yajl_tree_get(json_node, echo_path, yajl_t_string));
        if (ciphertext) {
            dec = aes_cbc_b64_decrypt((const unsigned char *)ciphertext, strlens(ciphertext),
                                      &decrypt_len, PASSWORD_STAND);
            if (!dec) {
                strcpy(decrypted_report, "/* error: Failed to decrypt. */");
                goto exit;
            }

            char tfa_report[decrypt_len + 1];
            memcpy(tfa_report, dec, decrypt_len);
            tfa_report[decrypt_len] = '\0';
            yajl_val tfa_node = yajl_tree_parse(tfa_report, NULL, 0);

            const char *tfa_path[] = { "2FA", (const char *) 0 };
            tfa = YAJL_GET_STRING(yajl_tree_get(tfa_node, tfa_path, yajl_t_string));
            if (tfa) {
                dec_tfa = aes_cbc_b64_decrypt((const unsigned char *)tfa, strlens(tfa), &dec_tfa_len,
                                              PASSWORD_2FA);
                if (!dec_tfa) {
                    strcpy(decrypted_report, "/* error: Failed to decrypt 2FA. */");
                    yajl_tree_free(tfa_node);
                    goto exit;
                }
                sprintf(decrypted_report, "/* 2FA */ %.*s", dec_tfa_len, dec_tfa);
                free(dec_tfa);
            } else {
                sprintf(decrypted_report, "/* ciphertext */ %.*s", decrypt_len, dec);
            }
            yajl_tree_free(tfa_node);
            free(dec);
            goto exit;
        } else if (echo) {
            dec = aes_cbc_b64_decrypt((const unsigned char *)echo, strlens(echo), &decrypt_len,
                                      PASSWORD_VERIFY);
            if (!dec) {
                strcpy(decrypted_report, "/* error: Failed to decrypt echo. */");
                goto exit;
            }

            char pin_report[decrypt_len + 1];
            memcpy(pin_report, dec, decrypt_len);
            pin_report[decrypt_len] = '\0';
            yajl_val pin_node = yajl_tree_parse(pin_report, NULL, 0);

            const char *pin_path[] = { CMD_STR[CMD_pin_], (const char *) 0 };
            pin = YAJL_GET_STRING(yajl_tree_get(pin_node, pin_path, yajl_t_string));
            if (pin) {
                memcpy(PIN_2FA, pin, 4);
            } else {
                memset(PIN_2FA, 0, sizeof(PIN_2FA));
            }
            sprintf(decrypted_report, "/* echo */ %.*s", decrypt_len, dec);
            yajl_tree_free(pin_node);
            free(dec);
            goto exit;
        }
    }
    strcpy(decrypted_report, report);
exit:
    yajl_tree_free(json_node);
    return;
}


void utils_send_cmd(const char *command, PASSWORD_ID enc_id)
{
    if (enc_id == PASSWORD_NONE) {
        utils_decrypt_report(commander(command));
    } else {
        int encrypt_len;
        char *enc = aes_cbc_b64_encrypt((const unsigned char *)command, strlens(command),
                                        &encrypt_len,
                                        enc_id);
        char cmd[COMMANDER_REPORT_SIZE] = {0};
        memcpy(cmd, enc, encrypt_len < COMMANDER_REPORT_SIZE ? encrypt_len :
               COMMANDER_REPORT_SIZE);
        free(enc);
        utils_decrypt_report(commander(cmd));
    }
}


#ifdef TESTING

void utils_send_print_cmd(const char *command, PASSWORD_ID enc_id)
{
    printf("\nutils send:   %s\n", command);
    utils_send_cmd(command, enc_id);
    printf("utils recv:   %s\n\n", decrypted_report);
}


#endif
