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


#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "commander.h"
#include "random.h"
#include "memory.h"
#include "base64.h"
#include "touch.h"
#include "utils.h"
#include "sha2.h"
#include "keys.h"
#include "jsmn.h"
#include "aes.h"
#include "led.h"
#include "sd.h"
#ifndef TESTING
#include <asf.h> /* Atmel Software Framework */
#include "ataes132.h" /* Atmel AES132 crypto chip */
#else

void delay_ms(int delay) { (void)delay; }

#endif


const char *CMD_STR[] = { FOREACH_CMD(GENERATE_STRING) };
const char *ATTR_STR[] = { FOREACH_ATTR(GENERATE_STRING) };

static char json_report[JSON_REPORT_SIZE] = {0};
static int REPORT_BUF_OVERFLOW = 0;
static int BUTTON_TOUCHED = 0;


// TODO use msg and error codes to pass to fill_report
void fill_report(const char *attr, const char *val, int err)
{
	fill_report_len(attr, val, err, strlen(val));
}


void fill_report_len(const char *attr, const char *val, int err, int vallen)
{
    size_t len = strlen(json_report);
    if (len == 0) {
        strncat(json_report, "{", 1);
    } else {    
        json_report[len - 1] = ','; // replace closing '}' with continuing ','
    }

    if (len > (JSON_REPORT_SIZE - (21 + strlen(attr) + strlen(val))) || len > (JSON_REPORT_SIZE - 128)) {
        // TEST the overflow error condition
        if (!REPORT_BUF_OVERFLOW) {
            strcat(json_report, "{ \"output\":{ \"error\":\"Buffer overflow.\"} }");
            REPORT_BUF_OVERFLOW = 1;
        }
    } else {
        strcat(json_report, " \"");
        strcat(json_report, attr);
        if (err == ERROR) { 
            strcat(json_report, "\":{ \"error\":\""); 
        } else {
            strcat(json_report, "\":\""); 
        }
        strncat(json_report, val, vallen); 
        
        // Add closing '}'
		if (err == ERROR) { 
            strcat(json_report, "\" } }"); 
        } else {
            strcat(json_report, "\" }"); 
        }
    }
}


static void device_reset(const char *r)
{
    if (r) { 
        if (strncmp(r, ATTR_STR[ATTR___ERASE___], strlen(ATTR_STR[ATTR___ERASE___])) == 0) { 
            led_state("enable");
			led_on();
            if (touch_button_press()) { delay_ms(1500);
            if (touch_button_press()) { delay_ms(1500);
            if (touch_button_press()) {
                memory_erase();
				memset(json_report, 0, JSON_REPORT_SIZE);
                fill_report("reset", "success", SUCCESS);
            }}}
            return; 
        }
    }
    fill_report("reset", "Incorrect syntax.", ERROR);
}


static void process_load(char *message)
{
    int wallet_len, mnemonic_len, sd_file_len, salt_len, decrypt_len;
    const char *mnemonic = jsmn_get_value_string(message, CMD_STR[CMD_mnemonic_], &mnemonic_len);
    const char *sd_file = jsmn_get_value_string(message, CMD_STR[CMD_sd_file_], &sd_file_len);
    const char *decrypt = jsmn_get_value_string(message, CMD_STR[CMD_decrypt_], &decrypt_len);
    const char *wallet = jsmn_get_value_string(message, CMD_STR[CMD_wallet_], &wallet_len);
    const char *salt = jsmn_get_value_string(message, CMD_STR[CMD_salt_], &salt_len);
    if (wallet) {
        if (!BUTTON_TOUCHED) {
            if (touch_button_press()) { BUTTON_TOUCHED = 1; }
        }
        if (BUTTON_TOUCHED) {
            if (mnemonic) {
                if (strncmp(wallet, ATTR_STR[ATTR_electrum_], strlen(ATTR_STR[ATTR_electrum_])) == 0) {
                    master_from_mnemonic_electrum(mnemonic, mnemonic_len);
                } else if (strncmp(wallet, ATTR_STR[ATTR_bip32_], strlen(ATTR_STR[ATTR_bip32_])) == 0) {
                    master_from_mnemonic_bip32((char *)mnemonic, mnemonic_len, salt, salt_len, 0);
                } 
            } else if (sd_file) {
                char *mnemo = load_sd(sd_file, sd_file_len);
                if (decrypt ? strncmp(decrypt, "no", 2) : 1) { // default = decrypt
                    int dec_len;
                    char *dec = aes_cbc_b64_decrypt((unsigned char *)mnemo, strlen(mnemo), memory_aeskey_read(), &dec_len);
                    memset(mnemo, 0, strlen(mnemo));
                    memcpy(mnemo, dec, dec_len);
                    memset(dec, 0, dec_len);
                    free(dec);							
                }
                //fill_report("debug sd read", mnemo, SUCCESS); // debug

                if (mnemo) {
                    if (strncmp(wallet, ATTR_STR[ATTR_electrum_], strlen(ATTR_STR[ATTR_electrum_])) == 0) {
                        master_from_mnemonic_electrum(mnemo, strlen(mnemo));
                    } else if (strncmp(wallet, ATTR_STR[ATTR_bip32_], strlen(ATTR_STR[ATTR_bip32_])) == 0) {
                        master_from_mnemonic_bip32(mnemo, strlen(mnemo), salt, salt_len, 0);
                    }
                }
            } else {
                fill_report("load", "A mnemonic or micro SD card filename not provided.", ERROR);
            }
        }  
    } else {
        fill_report("load", "Invalid command.", ERROR);
    }
}
			

static void process_seed(char *message)
{ 
    int wallet_len, salt_len;
    const char *wallet = jsmn_get_value_string(message, CMD_STR[CMD_wallet_], &wallet_len);
    const char *salt = jsmn_get_value_string(message, CMD_STR[CMD_salt_], &salt_len);
    if (wallet) {
        if (!BUTTON_TOUCHED) {
            if (touch_button_press()) { BUTTON_TOUCHED = 1; }
        }
        if (BUTTON_TOUCHED) {
            if (strncmp(wallet, ATTR_STR[ATTR_electrum_], strlen(ATTR_STR[ATTR_electrum_])) == 0) {
                master_from_mnemonic_electrum(NULL, 0);
            } else if (strncmp(wallet, ATTR_STR[ATTR_bip32_],strlen(ATTR_STR[ATTR_bip32_])) == 0) {
                master_from_mnemonic_bip32(NULL, 0, salt, salt_len, jsmn_get_value_uint(message, CMD_STR[CMD_strength_]));
            }
        }
    } else {
        fill_report("seed", "Invalid command.", ERROR);
    }   
}


static void process_backup(char *message)
{ 
    int wallet_len, encrypt_len, format_len, filename_len;
    const char *wallet = jsmn_get_value_string(message, CMD_STR[CMD_wallet_], &wallet_len);
    const char *format = jsmn_get_value_string(message, CMD_STR[CMD_format_sd_card_], &format_len);
    const char *encrypt = jsmn_get_value_string(message, CMD_STR[CMD_encrypt_], &encrypt_len);
    const char *filename = jsmn_get_value_string(message, CMD_STR[CMD_filename_], &filename_len);
    if (format ? !strncmp(format, "yes", 3) : 0) { // default = do not format
        if (!BUTTON_TOUCHED) {
            if (touch_button_press()) { BUTTON_TOUCHED = 1; }
        }
        if (BUTTON_TOUCHED) {
            if (format_sd()) {
                return; // could not format
            }
        } else {
            return; // button not touched
        }
    }
    if (!filename || !wallet) {
        if (!(format && !filename && !wallet)) {
            fill_report("backup", "Incomplete command.", ERROR);
        }
    } else {
        if (!BUTTON_TOUCHED) {
            if (touch_button_press()) { BUTTON_TOUCHED = 1; }
        }
        if (BUTTON_TOUCHED) {
            if (strncmp(wallet, ATTR_STR[ATTR_electrum_], strlen(ATTR_STR[ATTR_electrum_])) == 0) {
                char *text = mnemonic_from_seed_electrum(memory_electrum_mnemonic(NULL));
                if (!text) {
                    fill_report("backup", "Electrum mnemonic not present.", ERROR);
                } else if (encrypt ? strncmp(encrypt, "no", 2) : 1) { // default = encrypt
                    int enc_len;
                    char *enc = aes_cbc_b64_encrypt((unsigned char *)text, strlen(text), memory_aeskey_read(), &enc_len);
                    backup_sd(filename, filename_len, enc, enc_len);
                    free(enc);
                } else {
                    backup_sd(filename, filename_len, text, strlen(text));  
                }
            } else if (strncmp(wallet, ATTR_STR[ATTR_bip32_], strlen(ATTR_STR[ATTR_bip32_])) == 0) {
                char *text = mnemonic_from_index_bip32(memory_bip32_mnemonic(NULL)); // TEST
                if (!text) {
                    fill_report("backup", "BIP32 mnemonic not present.", ERROR);
                } else if (encrypt ? strncmp(encrypt, "no", 2) : 1) { // default = encrypt	
                    int enc_len;
                    char *enc = aes_cbc_b64_encrypt((unsigned char *)text, strlen(text), memory_aeskey_read(), &enc_len);
                    backup_sd(filename, filename_len, enc, enc_len);
                    free(enc);
                } else {
                    backup_sd(filename, filename_len, text, strlen(text));  
                }
            }
        }
    }	
}


static void process_sign(char *message)
{ 
    int wallet_len, data_len, keypath_len, encoding_len;		
    const char *data = jsmn_get_value_string(message,CMD_STR[CMD_data_], &data_len);
    const char *wallet = jsmn_get_value_string(message,CMD_STR[CMD_wallet_], &wallet_len);
    const char *keypath = jsmn_get_value_string(message,CMD_STR[CMD_keypath_], &keypath_len);
    const char *encoding = jsmn_get_value_string(message,CMD_STR[CMD_encoding_], &encoding_len);
    
    int enc;
    if (!wallet || !data || !encoding || !keypath) {
        fill_report("sign", "Incomplete command.", ERROR);
        return;  
    } else if (strncmp(encoding, ATTR_STR[ATTR_der_], strlen(ATTR_STR[ATTR_der_])) == 0) { 
        enc = ATTR_der_; 
    } else if (strncmp(encoding, ATTR_STR[ATTR_message_], strlen(ATTR_STR[ATTR_message_])) == 0) { 
        enc = ATTR_message_; 
    } else if (strncmp(encoding, ATTR_STR[ATTR_none_], strlen(ATTR_STR[ATTR_none_])) == 0) { 
        enc = ATTR_none_; 
    } else { 
        fill_report("sign", "Invalid encoding method.", ERROR); 
        return;  
    }
   
    if (!BUTTON_TOUCHED) {
        if (touch_button_press()) { BUTTON_TOUCHED = 1; }
    }
    if (BUTTON_TOUCHED) {
        if (strncmp(wallet, ATTR_STR[ATTR_electrum_], strlen(ATTR_STR[ATTR_electrum_])) == 0) {
            sign_electrum(data, data_len, (char *)keypath, enc);
        } else if (strncmp(wallet, ATTR_STR[ATTR_bip32_], strlen(ATTR_STR[ATTR_bip32_])) == 0) {
            sign_bip32(data, data_len, (char *)keypath, enc);
        } else {
            fill_report("sign", "Invalid wallet type.", ERROR);
            return;
        }
    }
}


static void process_random(char *message)
{ 
    int update_seed;
    uint8_t number[16];
    if (strcmp(message, ATTR_STR[ATTR_true_]) == 0) {
        update_seed = 1;
    } else if (strcmp(message, ATTR_STR[ATTR_pseudo_]) == 0) {
        update_seed = 0;
    } else {
        fill_report("random", "Invalid command.", ERROR);
        return;
    }

    if (random_bytes(number, sizeof(number), update_seed)) {
        fill_report("random", "Chip communication error.", ERROR);
    } else {
        fill_report("random", uint8_to_hex(number,sizeof(number)), SUCCESS);
    }
}


static int commander_process_token(int cmd, char *message)
{
    switch (cmd) {
        case CMD_reset_:
            device_reset(message);
            return -1;
        
        case CMD_password_:
		    memory_aeskey_write(message, strlen(message));
            break;
       
        case CMD_load_:
            process_load(message);
            break; 
        
        case CMD_seed_:
            process_seed(message);
            break;
        
        case CMD_backup_:
            process_backup(message);
            break;
                        
        case CMD_sign_:
            process_sign(message);
            break;
        
        case CMD_led_:
		    fill_report("led", (char *)led_state(message), SUCCESS);
            break;
        
        case CMD_name_:
            fill_report("name", (char *)memory_name(message), SUCCESS);
            break;        
        
        case CMD_random_:
            process_random(message);
            break;
        
        case CMD_master_public_key_: {
            if (strcmp(message, ATTR_STR[ATTR_electrum_]) == 0) {
                report_master_public_key_electrum();
	        } else if (strcmp(message, ATTR_STR[ATTR_bip32_]) == 0) {
                report_master_public_key_bip32();
            } else {
                fill_report("master_public_key", "Invalid command.", ERROR);
            }
            break;
        }
        
        case CMD_touchbutton_: {
		    // TEST disable function
            int status_len;
            const char *status = jsmn_get_value_string(message, CMD_STR[CMD_button_], &status_len);
            int s = -1; 
            if (status) {
                if (strncmp(status, ATTR_STR[ATTR_disable_], strlen(ATTR_STR[ATTR_disable_])) == 0) { s = 0; }
                else if (strncmp(status, ATTR_STR[ATTR_enable_], strlen(ATTR_STR[ATTR_enable_])) == 0) { s = 1; }
			}
            touch_button_parameters(jsmn_get_value_uint(message,CMD_STR[CMD_timeout_]), 
                                    jsmn_get_value_uint(message, CMD_STR[CMD_threshold_]), s);
            break;
        }

        case CMD_device_: {
            if (strcmp(message, ATTR_STR[ATTR_serial_]) == 0) {
	            fill_report("serial", "...", SUCCESS); // TODO get serial number
            } else if (strcmp(message, ATTR_STR[ATTR_version_]) == 0) {
                fill_report("version", (char *)DIGITAL_BITBOX_VERSION, SUCCESS);
            } else {
                fill_report("device", "Invalid command.", ERROR);
            }
            break;
        }
        
        case CMD_none_:
            break;
    }
    return 0;
}


char *commander(const char *instruction_encrypted)
{
    //printf("Command:\t%lu %s\n",strlen(instruction_encrypted),instruction_encrypted);
    memset(json_report, 0, JSON_REPORT_SIZE);
    //memory_load_parameters();
    REPORT_BUF_OVERFLOW = 0;
    BUTTON_TOUCHED = 0;
    led_on();


    long long int i; 
    int d = memory_delay_read();
    //printf("delay %i\n",d);
    for (i = 0; i < d * d * d * d; i++) {
        // After 3rd try, delay 4 sec
        // After 10th try, delay 8 min
        // After 20th try, delay 2.2 hrs
        // After 50th try, delay 3.6 days
        delay_ms(50);
    }

    if (!instruction_encrypted) {
        fill_report("input", "A valid command was not found.", ERROR);
    }
    
    else if (!strlen(instruction_encrypted)) {
        fill_report("input", "A valid command was not found.", ERROR);
    }
    
    // In case of a forgotten password, allow reset from an unencrypted instructions.
    else if (strstr(instruction_encrypted, CMD_STR[CMD_reset_]) != NULL) {
        int r_len;
        const char *r = jsmn_get_value_string(instruction_encrypted, CMD_STR[CMD_reset_], &r_len);
        device_reset(r);
	}
    
    // Force setting a password for encryption before processing instructions.
    else if (memory_erased_read()) {		
        if (strstr(instruction_encrypted, CMD_STR[CMD_password_]) != NULL) {
            memory_erase();
            memset(json_report, 0, JSON_REPORT_SIZE);
            int pw_len;
            const char *pw = jsmn_get_value_string(instruction_encrypted, CMD_STR[CMD_password_], &pw_len);
            if (pw != NULL) {
                if (memory_aeskey_write(pw, pw_len)) { memory_erased_write(0); }
            } else {
                fill_report("input", "JSON parse error.", ERROR);
            }
        } else {
			fill_report("input", "Please set a password.", ERROR);
		}
	}
	
    // Process one or more instructions.
    else
	{
        // Decrypt instructions
        int instruction_len;
		char *instruction = aes_cbc_b64_decrypt((unsigned char*)instruction_encrypted, 
                                                strlen(instruction_encrypted), 
                                                memory_aeskey_read(), 
                                                &instruction_len);
       
        // Parse instructions
	    if (instruction) {
            int r, j, cmd, found, msglen;
            jsmntok_t json_token[MAX_TOKENS];
            r = jsmn_parse_init(instruction, instruction_len, json_token, MAX_TOKENS);
            if (json_token[0].type != JSMN_OBJECT  ||  r < 0) 
            {
                fill_report("input", "JSON parse error. "
                            "Is the command enclosed by curly brackets?", ERROR);
            } else {
                found = 0;
                for (j = 0; j < r; j++) {
                    if (json_token[j].parent != 0)
                    {
                        continue; // skip child tokens
                    }
                    for (cmd = 0; cmd < CMD_NUM; cmd++) {    
                        if (jsmn_token_equals(instruction, &json_token[j], CMD_STR[cmd]) == 0) {
                            found = 1;
                            msglen = json_token[j + 1].end-json_token[j + 1].start;
                            char message[msglen + 1];
                            memcpy(message, instruction + json_token[j + 1].start, msglen);
                            message[msglen] = '\0';
                            if (commander_process_token(cmd, message) < 0) {
                                free(instruction);
                                return json_report; // _reset_ called
                            }
                            memset(message, 0, msglen);
                            break;
                        }
                    }
                }
                if (found) {
                    memory_delay_iterate(0);
                } else {
                    // Assume incorrect password and exponentially 
                    // increase delay before processing next instructions 
                    memory_delay_iterate(1);
                    fill_report("input", "A valid command was not found. "
                                "The next instruction will be delayed.", ERROR);
                }
            }

            // Encrypt report
		    int encrypt_len;
		    char *encoded_report = aes_cbc_b64_encrypt((unsigned char *)json_report,
                                                    strlen(json_report), 
                                                    memory_aeskey_read(),
                                                    &encrypt_len);
		    memset(json_report, 0, JSON_REPORT_SIZE);
            fill_report_len("ciphertext", encoded_report, SUCCESS, encrypt_len);
            free(encoded_report);
		    memset(instruction, 0, instruction_len);
    	}
        free(instruction);
	}
	memory_clear_variables();
    delay_ms(100);
	led_off();
    return json_report;
}


// Must free() returned value (allocated inside base64() function)
char *aes_cbc_b64_encrypt(const unsigned char *in, int inlen, 
                           const uint8_t *key, int *out_b64len)
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
    aes_set_key(key, 32, ctx); 
    
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


char *aes_cbc_b64_decrypt(const unsigned char *in, int inlen, 
                           const uint8_t *key, int *decrypt_len)
{
    // unbase64
    int ub64len;
    unsigned char *ub64 = unbase64((char *)in, inlen, &ub64len);
    if (!ub64 || (ub64len % N_BLOCK)) {
        fill_report("input", "Invalid encryption.", ERROR);
        decrypt_len = 0;
        free(ub64);
        return NULL;
    }
    
    // Set cipher key
    aes_context ctx[1]; 
    memset(ctx, 0, sizeof(ctx));  
    aes_set_key(key, 32, ctx); 
    
    unsigned char dec_pad[ub64len - N_BLOCK];
    aes_cbc_decrypt(ub64 + N_BLOCK, dec_pad, ub64len / N_BLOCK - 1, ub64, ctx);
    memset(ub64, 0, ub64len);
    free(ub64);
  
    // Strip PKCS7 padding
    int padlen = dec_pad[ub64len - N_BLOCK - 1];
    char *dec = malloc(ub64len - N_BLOCK - padlen + 1); // +1 for null termination
    if (!dec)
    {
        fill_report("input", "Could not allocate enough memory for decryption.", ERROR);
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





