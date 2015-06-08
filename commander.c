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

#include "commander.h"
#include "random.h"
#include "memory.h"
#include "base64.h"
#include "wallet.h"
#include "utils.h"
#include "flags.h"
#include "sha2.h"
#include "jsmn.h"
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
static int verify_keypath_cnt = 0;
static char verify_keypath[COMMANDER_REPORT_SIZE] = {0};
static char verify_output[COMMANDER_REPORT_SIZE] = {0};
static char verify_input[COMMANDER_REPORT_SIZE] = {0};
static char json_report[COMMANDER_REPORT_SIZE] = {0};


// Must free() returned value (allocated inside base64() function)
char *aes_cbc_b64_encrypt(const unsigned char *in, int inlen, int *out_b64len, PASSWORD_ID id)
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
    for(pads = 0; pads < N_BLOCK - inlen % N_BLOCK; pads++ ){
        inpad[inlen + pads] = (N_BLOCK-inlen % N_BLOCK);
    }
    
    // Make a random initialization vector 
    random_bytes((uint8_t *)iv, N_BLOCK, 0);
    memcpy(enc_cat, iv, N_BLOCK);
    
    // CBC encrypt multiple blocks
    aes_cbc_encrypt( inpad, enc, inpadlen / N_BLOCK, iv, ctx );
    memcpy(enc_cat + N_BLOCK, enc, inpadlen);

    // base64 encoding      
    int b64len;
    char * b64;
    b64 = base64(enc_cat, inpadlen + N_BLOCK, &b64len);
    *out_b64len = b64len;
    return b64;
}


// Must free() returned value
char *aes_cbc_b64_decrypt(const unsigned char *in, int inlen, int *decrypt_len, PASSWORD_ID id)
{
	if (!in || inlen == 0) {
		return NULL;
	}
	
    // Unbase64
    int ub64len;
    unsigned char *ub64 = unbase64((char *)in, inlen, &ub64len);
    if (!ub64 || (ub64len % N_BLOCK)) {
        decrypt_len = 0;
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
    char *dec = malloc(ub64len - N_BLOCK - padlen + 1); // +1 for null termination
    if (!dec)
    {
        memset(dec_pad, 0, sizeof(dec_pad));
        decrypt_len = 0;
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

static void commander_clear_report(void)
{
	memset(json_report, 0, COMMANDER_REPORT_SIZE);
	//json_report[0] = '\0';
	REPORT_BUF_OVERFLOW = 0;	
}


static void commander_fill_report_len(const char *attr, const char *val, int err, int vallen)
{
    size_t len = strlen(json_report);
    if (len == 0) {
        strncat(json_report, "{", 1);
    } else {    
        json_report[len - 1] = ','; // replace closing '}' with continuing ','
    }

    if (len > (COMMANDER_REPORT_SIZE - (21 + strlen(attr) + strlen(val))) || len > (COMMANDER_REPORT_SIZE - 128)) {
        // TEST the overflow error condition
        if (!REPORT_BUF_OVERFLOW) {
            strcat(json_report, "{ \"output\":{ \"error\":\"Buffer overflow.\"} }");
            REPORT_BUF_OVERFLOW = 1;
        }
    } else {
        strcat(json_report, " \"");
        strcat(json_report, attr);
        if (err == ERROR) { 
            strcat(json_report, "\":{ \"error\": "); 
        } else {
            strcat(json_report, "\": "); 
        }
       
        if (val[0] == '{') {
            strncat(json_report, val, vallen); 
        } else {
            strcat(json_report, "\"");
            strncat(json_report, val, vallen); 
            strcat(json_report, "\"");
        }
        
        // Add closing '}'
		if (err == ERROR) { 
            strcat(json_report, " } }"); 
        } else {
            strcat(json_report, " }"); 
        }
    }
}


void commander_fill_report(const char *attr, const char *val, int err)
{
    commander_fill_report_len(attr, val, err, strlen(val));
}


void commander_fill_report_signature(const uint8_t *sig, const uint8_t *pubkey)
{
    size_t len = strlen(json_report);
    if (len == 0) {
        strncat(json_report, "{", 1);
    } else {    
        json_report[len - 1] = ','; // replace closing '}' with continuing ','
    }
    
    if (len > (COMMANDER_REPORT_SIZE - (40 + 64 + 33))) {
        if (!REPORT_BUF_OVERFLOW) {
            strcat(json_report, "{ \"output\":{ \"error\":\"Buffer overflow.\"} }");
            REPORT_BUF_OVERFLOW = 1;
        }
    } else {
        strcat(json_report, " \"sign\": {");
        
        strcat(json_report, "\"sig\":\"");
        strncat(json_report, utils_uint8_to_hex(sig, 64), 128);
        strcat(json_report, "\", ");

        strcat(json_report, "\"pubkey\":\"");
        strncat(json_report, utils_uint8_to_hex(pubkey, 33), 66);
        strcat(json_report, "\"");
        
        strcat(json_report, "} }");
    }
}


//
//  Command processing  //
//

void commander_force_reset(void)
{
    memory_erase();
	commander_clear_report();
    commander_fill_report("reset", FLAG_ERR_RESET, ERROR);
}


static void commander_process_reset(const char *r)
{
    if (r) { 
        if (strncmp(r, ATTR_STR[ATTR___ERASE___], strlen(ATTR_STR[ATTR___ERASE___])) == 0) { 
            if (touch_button_press(0) == TOUCHED) { delay_ms(100);
            if (touch_button_press(0) == TOUCHED) { delay_ms(100);
            if (touch_button_press(0) == TOUCHED) {                   
			    memory_erase();
                commander_clear_report();
                commander_fill_report("reset", "success", SUCCESS);
            }}}
            return; 
        }
    }
    commander_fill_report("reset", FLAG_ERR_INVALID_CMD, ERROR);
}


static void commander_process_name(const char *message)
{
    commander_fill_report("name", (char *)memory_name(message), SUCCESS);
}


static void commander_process_seed(const char *message)
{ 
    int salt_len, source_len, decrypt_len, ret;
    char *seed_word[25] = {NULL}; 
    const char *salt = jsmn_get_value_string(message, CMD_STR[CMD_salt_], &salt_len);
    const char *source = jsmn_get_value_string(message, CMD_STR[CMD_source_], &source_len);
    const char *decrypt = jsmn_get_value_string(message, CMD_STR[CMD_decrypt_], &decrypt_len);
   

    if (!memory_read_unlocked()) {
        commander_fill_report("seed", FLAG_ERR_DEVICE_LOCKED, ERROR);
        return;
    }

    if (!source) {
        commander_fill_report("seed", FLAG_ERR_INVALID_CMD, ERROR);
        return;
    }

    char src[source_len + 1];
    memcpy(src, source, source_len);
    src[source_len] = '\0';

	if (strcmp(src, ATTR_STR[ATTR_create_]) == 0) {
        ret = wallet_master_from_mnemonic(NULL, 0, salt, salt_len);
    } else if (wallet_split_seed(seed_word, src) > 1) { 
        ret = wallet_master_from_mnemonic(src, source_len, salt, salt_len);
    } else {
        char *mnemo = sd_load(src, source_len);
        if (mnemo && (decrypt ? !strncmp(decrypt, "yes", 3) : 0)) { // default = do not decrypt
            int dec_len;
            char *dec = aes_cbc_b64_decrypt((unsigned char *)mnemo, strlen(mnemo), &dec_len, PASSWORD_STAND);
            memset(mnemo, 0, strlen(mnemo));
            memcpy(mnemo, dec, dec_len);
            memset(dec, 0, dec_len);
            free(dec);							
        }
        if (mnemo) {
            ret = wallet_master_from_mnemonic(mnemo, strlen(mnemo), salt, salt_len);
        } else {
            ret = ERROR;
        }
    }
    
    if (ret == ERROR) {
        commander_fill_report("seed", FLAG_ERR_MNEMO_CHECK, ERROR); 
        return;
    } 
    
    if (ret == ERROR_MEM) {
        commander_fill_report("seed", FLAG_ERR_ATAES, ERROR); 
        return;
    }
    
    commander_fill_report("seed", "success", SUCCESS);
}


static void commander_process_backup(const char *message)
{ 
    int encrypt_len, filename_len, ret;
    const char *encrypt, *filename;
    char *text, *l;

    if (!memory_read_unlocked()) {
        commander_fill_report("backup", FLAG_ERR_DEVICE_LOCKED, ERROR);
        return;
    }
    
    if (!message) {
        commander_fill_report("backup", FLAG_ERR_INVALID_CMD, ERROR);
        return;
    }
    
	if (strcmp(message, ATTR_STR[ATTR_list_]) == 0) {
		sd_list();
		return;
	}
    
    if (strcmp(message, ATTR_STR[ATTR_erase_]) == 0) {
	    sd_erase();
	    return;
    }
	
    filename = jsmn_get_value_string(message, CMD_STR[CMD_filename_], &filename_len);
	if (!filename) {
        commander_fill_report("backup", FLAG_ERR_INVALID_CMD, ERROR);
        return;
    } 
    
    text = wallet_mnemonic_from_index(memory_mnemonic(NULL));
    if (!text) {
        commander_fill_report("backup", FLAG_ERR_BIP32_MISSING, ERROR);
        return;
    } 
    
    encrypt = jsmn_get_value_string(message, CMD_STR[CMD_encrypt_], &encrypt_len);
    if (encrypt ? !strncmp(encrypt, "yes", 3) : 0) { // default = do not encrypt	
        int enc_len;
        char *enc = aes_cbc_b64_encrypt((unsigned char *)text, strlen(text), &enc_len, PASSWORD_STAND);
        if (!enc) {
            commander_fill_report("backup", FLAG_ERR_ENCRYPT_MEM, ERROR);
            free(enc);
            return; 
        }
        ret = sd_write(filename, filename_len, enc, enc_len);
        if (ret != SUCCESS) {
            commander_fill_report("backup", FLAG_ERR_SD_WRITE, ERROR);
        } else {
            l = sd_load(filename, filename_len);
            if (l) { 
                if (memcmp(enc, l, enc_len)) {
                    commander_fill_report("backup", FLAG_ERR_SD_FILE_CORRUPT, ERROR);
                }
            }
        }
        free(enc);
    } else {
        ret = sd_write(filename, filename_len, text, strlen(text));
        if (ret != SUCCESS) {
            commander_fill_report("backup", FLAG_ERR_SD_WRITE, ERROR);
        } else {
            l = sd_load(filename, filename_len);
            if (l) {
                if (memcmp(text, l, strlen(text))) {
                   commander_fill_report("backup", FLAG_ERR_SD_FILE_CORRUPT, ERROR);
                }
            }
        }
    }	
}


static int commander_process_sign(const char *message)
{ 
    int data_len, keypath_len, type_len, to_hash = 0;
    const char *data, *keypath, *type;
       
    if (!message) {
        commander_fill_report("sign", FLAG_ERR_INVALID_CMD, ERROR);
        return ERROR;
    }
    
    type = jsmn_get_value_string(message, CMD_STR[CMD_type_], &type_len);
    data = jsmn_get_value_string(message, CMD_STR[CMD_data_], &data_len);
    keypath = jsmn_get_value_string(message, CMD_STR[CMD_keypath_], &keypath_len);
    
    if (!data || !keypath || !type) {
        commander_fill_report("sign", FLAG_ERR_INVALID_CMD, ERROR);
        return ERROR;  
    }
    
    if (strncmp(type, ATTR_STR[ATTR_transaction_], strlen(ATTR_STR[ATTR_transaction_])) == 0) {
        to_hash = 1;
    } else if (strncmp(type, ATTR_STR[ATTR_hash_], strlen(ATTR_STR[ATTR_hash_]))) {
        commander_fill_report("sign", FLAG_ERR_INVALID_CMD, ERROR);
        return ERROR;
    }
    
    return(wallet_sign(data, data_len, keypath, keypath_len, to_hash));
}


static void commander_process_random(const char *message)
{ 
    int update_seed;
    uint8_t number[16];
    
    if (!message) {
        commander_fill_report("random", FLAG_ERR_INVALID_CMD, ERROR);
        return;
    }
    
    if (strcmp(message, ATTR_STR[ATTR_true_]) == 0) {
        update_seed = 1;
    } else if (strcmp(message, ATTR_STR[ATTR_pseudo_]) == 0) {
        update_seed = 0;
    } else {
        commander_fill_report("random", FLAG_ERR_INVALID_CMD, ERROR);
        return;
    }

    if (random_bytes(number, sizeof(number), update_seed)) {
        commander_fill_report("random", FLAG_ERR_ATAES, ERROR);
        return;
    }
    
    commander_fill_report("random", utils_uint8_to_hex(number, sizeof(number)), SUCCESS);
}


static int commander_process_password(const char *message, int msg_len, PASSWORD_ID id)
{
    return(memory_write_aeskey(message, msg_len, id));
}


static void commander_process_verifypass(const char *message)
{
    int ret;
    uint8_t number[16];
    char *l, text[64 + 1];
   
    if (!memory_read_unlocked()) {
        commander_fill_report("verifypass", FLAG_ERR_DEVICE_LOCKED, ERROR);
        return;
    } 
    
    if (!message) {
        commander_fill_report("verifypass", FLAG_ERR_INVALID_CMD, ERROR);
        return;
    }
    
    if (strcmp(message, ATTR_STR[ATTR_create_]) == 0) {
        if (random_bytes(number, sizeof(number), 1)) {
            commander_fill_report("random", FLAG_ERR_ATAES, ERROR);
            return;
        }
        if (commander_process_password(utils_uint8_to_hex(number, sizeof(number)), sizeof(number) * 2, PASSWORD_VERIFY) != SUCCESS) {
            return;
        }
        commander_fill_report(ATTR_STR[ATTR_create_], "success", SUCCESS);
    
    } else if (strcmp(message, ATTR_STR[ATTR_export_]) == 0) {
        memcpy(text, utils_uint8_to_hex(memory_read_aeskey(PASSWORD_VERIFY), 32), 64 + 1);
        ret = sd_write(VERIFYPASS_FILENAME, sizeof(VERIFYPASS_FILENAME), text, 64 + 1);
		if (ret != SUCCESS) {
            commander_fill_report(ATTR_STR[ATTR_export_], FLAG_ERR_SD_WRITE, ERROR);
	        return;
        }
        l = sd_load(VERIFYPASS_FILENAME, sizeof(VERIFYPASS_FILENAME));
        if (!l) {
            commander_fill_report(ATTR_STR[ATTR_export_], FLAG_ERR_SD_FILE_CORRUPT, ERROR);
            return;
        }
        if (memcmp(text, l, strlen(text))) {
            commander_fill_report(ATTR_STR[ATTR_export_], FLAG_ERR_SD_FILE_CORRUPT, ERROR);
	        return;
        }
        commander_fill_report(ATTR_STR[ATTR_export_], "success", SUCCESS);

    } else {
        commander_fill_report("verifypass", FLAG_ERR_INVALID_CMD, ERROR);
    }
}


void commander_create_verifypass(void) {
    commander_process_verifypass(ATTR_STR[ATTR_create_]);
}
    

static void commander_process_xpub(const char *message)
{
    char xpub[112] = {0};
    if (message) {
        if (strlen(message)) {
            wallet_report_xpub(message, strlen(message), xpub);            
            if (xpub[0]) {
                commander_fill_report("xpub", xpub, SUCCESS);
            } else {
                commander_fill_report("xpub", FLAG_ERR_BIP32_MISSING, ERROR);
            }
            return;
        }
    }
    commander_fill_report("xpub", FLAG_ERR_INVALID_CMD, ERROR);
}


static void commander_process_device(const char *message)
{
    if (!message) {
        commander_fill_report("device", FLAG_ERR_INVALID_CMD, ERROR);
        return;
    }
    
    if (strcmp(message, ATTR_STR[ATTR_serial_]) == 0) {
        uint32_t serial[4];
        if (!flash_read_unique_id(serial, 16)) {
            commander_fill_report(ATTR_STR[ATTR_serial_], utils_uint8_to_hex((uint8_t *)serial, sizeof(serial)), SUCCESS);         
        } else {
            commander_fill_report(ATTR_STR[ATTR_serial_], FLAG_ERR_FLASH, ERROR);         
        }
        return;
    } 
    
    if (strcmp(message, ATTR_STR[ATTR_version_]) == 0) {
        commander_fill_report(ATTR_STR[ATTR_version_], (char *)DIGITAL_BITBOX_VERSION, SUCCESS);
        return;
    } 
    
    if (strcmp(message, ATTR_STR[ATTR_lock_]) == 0) {
        memory_write_unlocked(0); 
        commander_fill_report("device", "locked", SUCCESS);
        return;
    }
    
    commander_fill_report("device", FLAG_ERR_INVALID_CMD, ERROR);
}


static void commander_process_aes256cbc(const char *message)
{ 
    int type_len, data_len, crypt_len;
    const char *type, *data;
    char *crypt;
       
    if (!message) {
        commander_fill_report("aes256cbc", FLAG_ERR_INVALID_CMD, ERROR);
        return;
    }
    
    type = jsmn_get_value_string(message, CMD_STR[CMD_type_], &type_len);
    data = jsmn_get_value_string(message, CMD_STR[CMD_data_], &data_len);
    
    if (!type || !data) {
        commander_fill_report("aes256cbc", FLAG_ERR_INVALID_CMD, ERROR);
        return;  
    }
   
    if (strncmp(type, ATTR_STR[ATTR_password_], strlen(ATTR_STR[ATTR_password_])) == 0) {
        if (commander_process_password(data, data_len, PASSWORD_CRYPT) == SUCCESS) {
            commander_fill_report("aes256cbc", "success", SUCCESS);
        }
    } 
    else if (memory_aeskey_is_erased(PASSWORD_CRYPT) == ERASED) {
        commander_fill_report("aes256cbc", FLAG_ERR_NO_PASSWORD, ERROR);
    } 
    else if (strncmp(type, ATTR_STR[ATTR_encrypt_], strlen(ATTR_STR[ATTR_encrypt_])) == 0) {
        if (data_len > DATA_LEN_MAX) {
            commander_fill_report("aes256cbc", FLAG_ERR_DATA_LEN, ERROR);
        } else {
            crypt = aes_cbc_b64_encrypt((unsigned char *)data, data_len, &crypt_len, PASSWORD_CRYPT); 
            commander_fill_report_len("aes256cbc", crypt, SUCCESS, crypt_len);
            free(crypt);
        }
    } 
    else if (strncmp(type, ATTR_STR[ATTR_decrypt_], strlen(ATTR_STR[ATTR_decrypt_])) == 0) {
        crypt = aes_cbc_b64_decrypt((unsigned char *)data, data_len, &crypt_len, PASSWORD_CRYPT);
        if (crypt) { 
            commander_fill_report_len("aes256cbc", crypt, SUCCESS, crypt_len);
        } else {
            commander_fill_report("aes256cbc", FLAG_ERR_DECRYPT, ERROR);
        } 
        free(crypt);
    } 
    else { 
        commander_fill_report("aes256cbc", FLAG_ERR_INVALID_CMD, ERROR);
    }
}


static void commander_process_led(const char *message)
{
    if (!message) {
        commander_fill_report("led", FLAG_ERR_INVALID_CMD, ERROR);
    } else if (strncmp(message, ATTR_STR[ATTR_toggle_], strlen(ATTR_STR[ATTR_toggle_])) != 0) {
        commander_fill_report("led", FLAG_ERR_INVALID_CMD, ERROR);
    } else {
        led_toggle(); delay_ms(300);	
        led_toggle();  
        commander_fill_report("led", "toggled", SUCCESS);
    }
}


static int commander_process(int cmd, char *message)
{
    switch (cmd) {
        case CMD_reset_:
            commander_process_reset(message);
            return RESET;
        
        case CMD_password_:
		    if (commander_process_password(message, strlen(message), PASSWORD_STAND) == SUCCESS) {
                commander_fill_report(CMD_STR[cmd], "success", SUCCESS);
            }
            break;
        
        case CMD_verifypass_:
            commander_process_verifypass(message);
            break;
        
        case CMD_led_:
            commander_process_led(message);
            break;
        
        case CMD_name_:
            commander_process_name(message);
            break;      
       
        case CMD_seed_:
            commander_process_seed(message);
            break;
        
        case CMD_backup_:
            commander_process_backup(message);
            break;
                        
        case CMD_sign_:
            return commander_process_sign(message);

        case CMD_random_:
            commander_process_random(message);
            break;
      
        case CMD_xpub_: 
            commander_process_xpub(message);
            break;

        case CMD_device_: 
            commander_process_device(message);
            break;
        
        case CMD_aes256cbc_: 
            commander_process_aes256cbc(message);
            break;
        
        case CMD_touchbutton_:
            touch_button_parameters(jsmn_get_value_uint(message, CMD_STR[CMD_timeout_]) * 1000, 
                                    jsmn_get_value_uint(message, CMD_STR[CMD_threshold_]));
            break;

        case CMD_none_:
            break;
    }
    return SUCCESS;
}


//
//  Handle API input (preprocessing) //
//

static void commander_echo_2fa(char *command)
{
    int encrypt_len;
    char *encoded_report;
    
    commander_clear_report();
    
    if (!memory_read_unlocked()) {
        // Create one-time PIN
        uint8_t pin_b[2];    
        char pin_c[5];
        random_bytes(pin_b, 2, 0);
        sprintf(pin_c, "%04d", (pin_b[1] * 256 + pin_b[0]) % 10000); // 0 to 9999

        // Append PIN to echoed command
        command[strlen(command) - 1] = ','; // replace closing '}' with continuing ','
        strcat(command, " \"");
        strcat(command, CMD_STR[CMD_pin_]);
        strcat(command, "\": \"");
        strcat(command, pin_c);
        strcat(command, "\" }");
        
        // Create 2FA AES key for encryption
        commander_process_password(pin_c, 4, PASSWORD_2FA); 
    }

    encoded_report = aes_cbc_b64_encrypt((unsigned char *)command,
                                            strlen(command), 
                                            &encrypt_len,
                                            PASSWORD_VERIFY); 
    commander_clear_report();
    
    if (encoded_report) {
        commander_fill_report_len("echo", encoded_report, SUCCESS, encrypt_len);
    } else {
        commander_fill_report("output", FLAG_ERR_ENCRYPT_MEM, ERROR);
    }
    free(encoded_report);
}
                        

static int commander_verify_signing(const char *message)
{
    int data_len, type_len, keypath_len, change_keypath_len;
    int ret, same_io, same_keypath, input_cnt;
    char *data, *type, *keypath, *change_keypath, *out;
    
    type = (char *)jsmn_get_value_string(message, CMD_STR[CMD_type_], &type_len);
    data = (char *)jsmn_get_value_string(message, CMD_STR[CMD_data_], &data_len);
    keypath = (char *)jsmn_get_value_string(message, CMD_STR[CMD_keypath_], &keypath_len);
    change_keypath = (char *)jsmn_get_value_string(message, CMD_STR[CMD_change_keypath_], &change_keypath_len);

    if (!data || !type) {
        commander_fill_report("sign", FLAG_ERR_INVALID_CMD, ERROR);
        return ERROR;  
    }
  
    if (strncmp(type, ATTR_STR[ATTR_transaction_], strlen(ATTR_STR[ATTR_transaction_])) == 0) 
    {
        // Check if deserialized inputs and outputs are the same (scriptSig's could be different).
        // The function updates verify_input and verify_output.
        same_io = wallet_check_input_output(data, data_len, verify_input, verify_output, &input_cnt);
       
        // Check if using the same signing keypath
        same_keypath = (!memcmp(keypath, verify_keypath, keypath_len) && 
                        (keypath_len == (int)strlen(verify_keypath))) ? SAME : DIFFERENT;
        memset(verify_keypath, 0, sizeof(verify_keypath));
        memcpy(verify_keypath, keypath, keypath_len);
        
        // Deserialize and check if a change address is present (when more than one output is given).
        out = wallet_deserialize_output(verify_output, strlen(verify_output), change_keypath, change_keypath_len);
        
        if (!out) {
            commander_fill_report("sign", FLAG_ERR_DESERIALIZE, ERROR);
            ret = ERROR;  
        } else if (same_io == SAME && same_keypath == SAME) {
            verify_keypath_cnt++;
            ret = SAME;
        } else if (same_io == SAME && same_keypath == DIFFERENT) {
            verify_keypath_cnt++;
            ret = NEXT;
        } else {
            verify_keypath_cnt = 0;
            commander_echo_2fa(out); 
            ret = DIFFERENT;
        }
        if (verify_keypath_cnt >= input_cnt) {
            memset(verify_input, 0, COMMANDER_REPORT_SIZE);
            memset(verify_output, 0, COMMANDER_REPORT_SIZE);
        }
        return(ret);
    } 
    else 
    {
        // Because data is hashed, check the whole command instead of only transaction inputs/outputs.
        // When 'locked', the commander_echo_2fa function replaces ending '}' with ',' and adds PIN 
		// information to the end of verify_output. Therefore, compare verify_output over strlen of
		// message minus 1 characters.
        if (memcmp(verify_output, message, strlen(message) - 1)) { 
            memset(verify_output, 0, COMMANDER_REPORT_SIZE);
            memcpy(verify_output, message, strlen(message));
            commander_echo_2fa(verify_output); 
            return DIFFERENT;
        } else {
            return SAME;
        }
    }
}


static int commander_touch_button(int found_cmd, const char *message)
{
    int t, c;
    
    if (found_cmd == CMD_sign_) {
        c = commander_verify_signing(message);
        if (c == SAME) {
            t = touch_button_press(1);
            if (t != TOUCHED) {
                // Clear previous signing information
                // to force touch for next sign command.
                memset(verify_input, 0, COMMANDER_REPORT_SIZE);
                memset(verify_output, 0, COMMANDER_REPORT_SIZE);
            }
            return(t);
        } else if (c == NEXT) {
            return TOUCHED; 
        } else if (c == DIFFERENT) {
            return ECHO; 
        } else {
            memset(verify_input, 0, COMMANDER_REPORT_SIZE);
            memset(verify_output, 0, COMMANDER_REPORT_SIZE);
            return ERROR;
        }
        
    } else if (found_cmd == CMD_seed_ && !memcmp(memory_master(NULL), MEM_PAGE_ERASE, 32)) {
        return TOUCHED;   
    } else if (found_cmd < CMD_require_touch_) {
        return(touch_button_press(0));

    } else {
        return TOUCHED;
    }
}


static void commander_parse(char *command, jsmntok_t json_token[MAX_TOKENS], int n_tokens)
{ 
    char *encoded_report;
    int j, t, cmd, ret, err, found, found_cmd = 0xFF, found_tok, msglen, encrypt_len;
    
    // Extract commands
	err = 0;
    found = 0;
    for (j = 0; j < n_tokens; j++) {
        if (json_token[j].parent != 0) {
            continue; // Skip child tokens
        }
        for (cmd = 0; cmd < CMD_NUM; cmd++) {    
            if (jsmn_token_equals(command, &json_token[j], CMD_STR[cmd]) == 0) 
            {                    
                found++;
                found_tok = j;
                found_cmd = cmd;
                break;
            }
        }
    }

    // Process commands
    if (!found) {
        commander_fill_report("input", FLAG_ERR_INVALID_CMD, ERROR);
    } else if (found > 1) {
        commander_fill_report("input", FLAG_ERR_MULTIPLE_CMD, ERROR);
    } else {
        memory_access_err_count(INITIALIZE);
        msglen = json_token[found_tok + 1].end-json_token[found_tok + 1].start;
        char message[msglen + 1];
        memcpy(message, command + json_token[found_tok + 1].start, msglen);
        message[msglen] = '\0';
        t = commander_touch_button(found_cmd, message);
        if (t == ECHO) {
            return;
        } else if (t == TOUCHED) {
            ret = commander_process(found_cmd, message);
            if (ret == RESET) {
                return;
            } else if (ret == ERROR) {
                err++;
            }
            memset(message, 0, msglen);
        } else {
            // error or not touched
			err++;
        }
		
		if (found_cmd == CMD_sign_ && !memory_read_unlocked() && !err) {
			encoded_report = aes_cbc_b64_encrypt((unsigned char *)json_report,
												  strlen(json_report),
												  &encrypt_len,
												  PASSWORD_2FA);
			commander_clear_report();
			if (encoded_report) {
				commander_fill_report_len("2FA", encoded_report, SUCCESS, encrypt_len);
				free(encoded_report);
			}
		}
    }
	
    encoded_report = aes_cbc_b64_encrypt((unsigned char *)json_report,
                                         strlen(json_report),
                                         &encrypt_len, 
                                         PASSWORD_STAND); 
    
    commander_clear_report();
    
    if (encoded_report) {
        commander_fill_report_len("ciphertext", encoded_report, SUCCESS, encrypt_len);
    } else {
        commander_fill_report("output", FLAG_ERR_ENCRYPT_MEM, ERROR);
    }
    free(encoded_report);
}


static char *commander_decrypt(const char *encrypted_command,  
                              jsmntok_t json_token[MAX_TOKENS],
                              int *n_tokens)
{
    char *command;
    int command_len = 0, n = 0, err = 0;
    uint16_t err_count = 0, err_iter = 0;

    command = aes_cbc_b64_decrypt((unsigned char *)encrypted_command, 
                                      strlen(encrypted_command), 
                                      &command_len,
                                      PASSWORD_STAND);
    
    err_count = memory_read_access_err_count(); // Reads over TWI introduce additional 
    err_iter = memory_read_access_err_count();  // temporal jitter in code execution.
    memset(json_token, 0, sizeof(jsmntok_t) * MAX_TOKENS);
    
    if (command == NULL) {
        err++;
        commander_fill_report("input", FLAG_ERR_DECRYPT " "           
                                       FLAG_ERR_RESET_WARNING, ERROR);
        err_iter = memory_access_err_count(ITERATE);
    } else {
        n = jsmn_parse_init(command, command_len, json_token, MAX_TOKENS);
    }
    *n_tokens = n;
    
    if (json_token[0].type != JSMN_OBJECT && err == 0)
    {
        err++;
        commander_fill_report("input", FLAG_ERR_JSON_PARSE " " 
                                       FLAG_ERR_RESET_WARNING " "
                                       FLAG_ERR_JSON_BRACKET, ERROR);
        err_iter = memory_access_err_count(ITERATE);
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
    if (!encrypted_command) {
        commander_fill_report("input", FLAG_ERR_NO_INPUT " "          
                                       FLAG_ERR_RESET_WARNING, ERROR);
        memory_access_err_count(ITERATE);
        return ERROR;
    } 
    
    if (!strlen(encrypted_command)) {
        commander_fill_report("input", FLAG_ERR_NO_INPUT " "
                                       FLAG_ERR_RESET_WARNING, ERROR);
        memory_access_err_count(ITERATE);
        return ERROR;
    }
    
    // In case of a forgotten password, allow reset from an unencrypted command.
    if (strstr(encrypted_command, CMD_STR[CMD_reset_]) != NULL) {
        int r_len;
        const char *r = jsmn_get_value_string(encrypted_command, CMD_STR[CMD_reset_], &r_len);
        commander_process_reset(r);
        return RESET;
	}
    
    // Force setting a password for encryption before processing command.
    if (!memory_read_erased()) {		
        return SUCCESS; 
    }
    if (strstr(encrypted_command, CMD_STR[CMD_password_]) != NULL) {
        int pw_len;
        const char *pw = jsmn_get_value_string(encrypted_command, CMD_STR[CMD_password_], &pw_len);
        if (pw != NULL) {
            if (commander_process_password(pw, pw_len, PASSWORD_STAND) == SUCCESS) { 
                memory_write_erased(0); 
                commander_fill_report(CMD_STR[CMD_password_], "success", SUCCESS);
            }
        } else {
            commander_fill_report("input", FLAG_ERR_JSON_PARSE, ERROR);
        }
    } else {
        commander_fill_report("input", FLAG_ERR_NO_PASSWORD, ERROR);
    }
    return ERROR;
}
 

//
//  Gateway to the MCU code //
//
char *commander(const char *command)
{
    int n_tokens;
	jsmntok_t json_token[MAX_TOKENS];

    commander_clear_report();

    if (commander_check_init(command) == SUCCESS) {
        char *command_dec = commander_decrypt(command, json_token, &n_tokens);
        if (command_dec) {
            commander_parse(command_dec, json_token, n_tokens);
        }
        free(command_dec);
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
            |    |
            |    \_commander_verify_signing()
            |         |--if new transaction -> echo 2FA info -> RETURN
            |         |--if no change address & >1 output -> RETURN
            |
            |--if require touch & not touched -> RETURN
            |
    \_commander_process()  { do command }
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
