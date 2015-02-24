/*

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


#include "utils.h"
#include <string.h>


uint8_t *hex_to_uint8(const char *str)
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


char *uint8_to_hex(const uint8_t *bin, size_t l)
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


#ifdef TESTING
#include <stdio.h>
#include <stdlib.h>
#include "commander.h"
#include "memory.h"
#include "jsmn.h"
#include "sha2.h"


extern const char *CMD_STR[];


uint8_t *utils_double_sha256(const uint8_t *msg, uint32_t msg_len)
{
	static uint8_t hash[32];
    memset(hash, 0, 32);
    sha256_Raw(msg, msg_len, hash);
	sha256_Raw(hash, 32, hash);
    return hash;
}


void utils_print_report(const char *report, PASSWORD_ID dec_id)
{
    int decrypt_len, r, i, len;
    char cipher[COMMANDER_REPORT_SIZE], *dec;
    jsmntok_t json_token[MAX_TOKENS];
    r = jsmn_parse_init(report, strlen(report), json_token, MAX_TOKENS);
     
    if (r < 0) {
        printf("Failed to parse report:  %s\n", report);
        return;
    }
    
    for (i = 0; i < r; i++) {
        len = json_token[i + 1].end - json_token[i + 1].start;
        if (jsmn_token_equals(report, &json_token[i], CMD_STR[CMD_ciphertext_]) == 0) {
            memcpy(cipher, report + json_token[i + 1].start, len);
            cipher[len] = '\0';
            dec = aes_cbc_b64_decrypt((unsigned char *)cipher, strlen(cipher), &decrypt_len, dec_id);
            printf("ciphertext:\t%.*s\n\n", decrypt_len, dec);
            free(dec);
            return;
        } else if (jsmn_token_equals(report, &json_token[i], CMD_STR[CMD_echo_]) == 0) {
            memcpy(cipher, report + json_token[i + 1].start, len);
            cipher[len] = '\0';
            dec = aes_cbc_b64_decrypt((unsigned char *)cipher, strlen(cipher), &decrypt_len, dec_id);
            printf("echo:      \t%.*s\n", decrypt_len, dec);
            free(dec);
            return;
    
        }
    }
    printf("report:    \t%s\n\n",report);
}


void utils_send_cmd(const char *command, PASSWORD_ID enc_id, PASSWORD_ID dec_id)
{
    if (enc_id == PASSWORD_NONE) {
        utils_print_report(commander(command), dec_id);
    } else {
        int encrypt_len;
        char *enc = aes_cbc_b64_encrypt((unsigned char *)command, strlen(command), &encrypt_len, enc_id);
        utils_print_report(commander(enc), dec_id);
        free(enc); 
    }
}


// Send command twice in case of command being echoed (i.e. when touch button is required)
void utils_send_cmd_x2(const char *command, PASSWORD_ID enc_id, PASSWORD_ID dec_id)
{
    int encrypt_len;
    char *enc = aes_cbc_b64_encrypt((unsigned char *)command, strlen(command), &encrypt_len, enc_id);
    utils_print_report(commander(enc), dec_id);
    utils_print_report(commander(enc), dec_id);
    free(enc); 
}
#endif
