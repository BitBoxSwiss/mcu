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
#include "commander.h"
#include "flags.h"
#include "jsmn.h"

extern const char *CMD_STR[];
static char PIN_2FA[5] = {0};
static char decrypted_report[COMMANDER_REPORT_SIZE];


uint8_t *utils_hex_to_uint8(const char *str)
{
    if (strlen(str) > TO_UINT8_HEX_BUF_LEN) {
        return NULL;
    }
    static uint8_t buf[TO_UINT8_HEX_BUF_LEN];
    memset(buf, 0, sizeof(buf));
    uint8_t c;
    size_t i;
    for (i = 0; i < strlen(str) / 2; i++) {
        c = 0;
        if (str[i * 2] >= '0' && str[i * 2] <= '9') c += (str[i * 2] - '0') << 4;
        if (str[i * 2] >= 'a' && str[i * 2] <= 'f') c += (10 + str[i  *2] - 'a') << 4;
        if (str[i * 2] >= 'A' && str[i * 2] <= 'F') c += (10 + str[i * 2] - 'A') << 4;
        if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') c += (str[i * 2 + 1] - '0');
        if (str[i * 2 + 1] >= 'a' && str[i * 2 + 1] <= 'f') c += (10 + str[i * 2 + 1] - 'a');
        if (str[i * 2 + 1] >= 'A' && str[i * 2 + 1] <= 'F') c += (10 + str[i * 2 + 1] - 'A');
        buf[i] = c;
    }
    return buf;
}


char *utils_uint8_to_hex(const uint8_t *bin, size_t l)
{
    if ((l * 2) > TO_UINT8_HEX_BUF_LEN) {
        return NULL;
    }
    static char digits[] = "0123456789abcdef";
    static char buf[TO_UINT8_HEX_BUF_LEN];
    memset(buf, 0, sizeof(buf));
    size_t i;
    for (i = 0; i < l; i++) {
        buf[i * 2] = digits[(bin[i] >> 4) & 0xF];
        buf[i * 2 + 1] = digits[bin[i] & 0xF];
    }
    buf[l * 2] = 0;
    return buf;
}


void utils_reverse_hex(char *h, int len)
{
    char copy[len];
    strncpy(copy, h, len);
    int i;
    for (i = 0; i<len; i += 2) {
        h[i] = copy[len - i - 2];
        h[i + 1] = copy[len - i - 1];
    }
}


void utils_uint64_to_varint(char *vi, int *l, uint64_t i)
{
    int len;
    char v[VARINT_LEN];

    if (i<0xfd) {
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
    sscanf(v, "%" PRIx64 , i);

    return len;
}


char *utils_read_decrypted_report(void)
{
    return decrypted_report;
}


void utils_decrypt_report(const char *report)
{
    int decrypt_len, pin_len, tfa_len, dec_tfa_len, r, i;
    char *dec, *pin, *tfa, *dec_tfa;
    jsmntok_t json_token[MAX_TOKENS];

    memset(decrypted_report, 0, sizeof(decrypted_report));
    r = jsmn_parse_init(report, strlen(report), json_token, MAX_TOKENS);

    if (r < 0) {
        strcpy(decrypted_report, "error: Failed to parse report.");
        return;
    }

    for (i = 0; i < r; i++) {
        int len = json_token[i + 1].end - json_token[i + 1].start;
        if (jsmn_token_equals(report, &json_token[i], CMD_STR[CMD_ciphertext_]) == 0) {
            memcpy(decrypted_report, report + json_token[i + 1].start, len);
            decrypted_report[len] = '\0';
            dec = aes_cbc_b64_decrypt((unsigned char *)decrypted_report, strlen(decrypted_report), &decrypt_len, PASSWORD_STAND);
            tfa = (char *)jsmn_get_value_string(dec, "2FA", &tfa_len);
            if (tfa) {
                dec_tfa = aes_cbc_b64_decrypt((unsigned char *)tfa, tfa_len, &dec_tfa_len, PASSWORD_2FA);
                sprintf(decrypted_report, "2FA: %.*s", dec_tfa_len, dec_tfa);

                free(dec_tfa);
            } else {
                sprintf(decrypted_report, "ciphertext: %.*s", decrypt_len, dec);
            }
            free(dec);
            return;
        } else if (jsmn_token_equals(report, &json_token[i], "echo") == 0) {
            memcpy(decrypted_report, report + json_token[i + 1].start, len);
            decrypted_report[len] = '\0';
            dec = aes_cbc_b64_decrypt((unsigned char *)decrypted_report, strlen(decrypted_report), &decrypt_len, PASSWORD_VERIFY);
            pin = (char *)jsmn_get_value_string(dec, CMD_STR[CMD_pin_], &pin_len);
            if (pin) {
                memcpy(PIN_2FA, pin, 4);
            } else {
                memset(PIN_2FA, 0, sizeof(PIN_2FA));
            }
            sprintf(decrypted_report, "echo: %.*s", decrypt_len, dec);
            free(dec);
            return;
        }
    }
    strcpy(decrypted_report, report);
    return;
}


void utils_send_cmd(const char *command, PASSWORD_ID enc_id)
{
    if (enc_id == PASSWORD_NONE) {
        utils_decrypt_report(commander(command));
    } else {
        int encrypt_len;
        char *enc = aes_cbc_b64_encrypt((unsigned char *)command, strlen(command), &encrypt_len, enc_id);
        char cmd[COMMANDER_REPORT_SIZE] = {0};
        memcpy(cmd, enc, encrypt_len < COMMANDER_REPORT_SIZE ? encrypt_len : COMMANDER_REPORT_SIZE);
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
