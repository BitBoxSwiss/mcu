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
#include "wallet.h"
#include "utils.h"
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


const char *CMD_STR[] = { FOREACH_CMD(GENERATE_STRING) };
const char *ATTR_STR[] = { FOREACH_ATTR(GENERATE_STRING) };


static char verify_output[COMMANDER_REPORT_SIZE] = {0};
static char verify_input[COMMANDER_REPORT_SIZE] = {0};
static char json_report[COMMANDER_REPORT_SIZE] = {0};
static int REPORT_BUF_OVERFLOW = 0;
static int SIG_COUNT = 0;


static void commander_clear_report(void)
{
	memset(json_report, 0, COMMANDER_REPORT_SIZE);
	REPORT_BUF_OVERFLOW = 0;	
    SIG_COUNT = 0;
}


void commander_fill_report(const char *attr, const char *val, int err)
{
    commander_fill_report_len(attr, val, err, strlen(val));
}


void commander_fill_report_len(const char *attr, const char *val, int err, int vallen)
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


void commander_fill_report_signature(const uint8_t *sig, const uint8_t *pubkey, const char *id, size_t id_len)
{
    size_t len = strlen(json_report);
    if (len == 0) {
        strncat(json_report, "{", 1);
    } else {    
        json_report[len - 1] = ','; // replace closing '}' with continuing ','
    }
    
    if (len > (COMMANDER_REPORT_SIZE - (40 + 64 + 33 + id_len))) {
        if (!REPORT_BUF_OVERFLOW) {
            strcat(json_report, "{ \"output\":{ \"error\":\"Buffer overflow.\"} }");
            REPORT_BUF_OVERFLOW = 1;
        }
    } else {
        if (SIG_COUNT == 0) {
            strcat(json_report, " \"sign\": ");
            //strcat(json_report, " \"sign\":[");
        } else {    
            json_report[len - 2] = ','; // replace closing ']}' with continuing ', '
            json_report[len - 1] = ' '; // replace closing ']}' with continuing ', '
        }
        strcat(json_report, "{");
        
        strcat(json_report, "\"id\":\"");
        strncat(json_report, id, id_len);
        strcat(json_report, "\", ");

        strcat(json_report, "\"sig\":\"");
        strncat(json_report, uint8_to_hex(sig, 64), 128);
        strcat(json_report, "\", ");

        strcat(json_report, "\"pubkey\":\"");
        strncat(json_report, uint8_to_hex(pubkey, 33), 66);
        strcat(json_report, "\"");
        
        strcat(json_report, "}");

        // Add closing ']}'
        strcat(json_report, " }"); 
        //strcat(json_report, "]}"); 
    }

    SIG_COUNT++;
}


void commander_force_reset(void)
{
    memory_erase();
	commander_clear_report();
    commander_fill_report("reset", "Too many failed access attempts. Device reset.", ERROR);
}


static void device_reset(const char *r)
{
    if (r) { 
        if (strncmp(r, ATTR_STR[ATTR___ERASE___], strlen(ATTR_STR[ATTR___ERASE___])) == 0) { 
            if (!touch_button_press(0)) { //delay_ms(1000);
            if (!touch_button_press(0)) { //delay_ms(1000);
            if (!touch_button_press(0)) {
                memory_erase();
                commander_clear_report();
                commander_fill_report("reset", "success", SUCCESS);
            }}}
            return; 
        }
    }
    commander_fill_report("reset", "Incorrect syntax.", ERROR);
}


static void process_load(char *message)
{
    int mnemonic_len, sd_file_len, salt_len, decrypt_len;
    const char *mnemonic = jsmn_get_value_string(message, CMD_STR[CMD_mnemonic_], &mnemonic_len);
    const char *filename = jsmn_get_value_string(message, CMD_STR[CMD_filename_], &sd_file_len);
    const char *decrypt = jsmn_get_value_string(message, CMD_STR[CMD_decrypt_], &decrypt_len);
    const char *salt = jsmn_get_value_string(message, CMD_STR[CMD_salt_], &salt_len);
    if (mnemonic) {
        wallet_master_from_mnemonic((char *)mnemonic, mnemonic_len, salt, salt_len, 0);
    } else if (filename) {
        char *mnemo = sd_load(filename, sd_file_len);
        if (mnemo && (decrypt ? !strncmp(decrypt, "yes", 3) : 0)) { // default = do not decrypt
            int dec_len;
            char *dec = aes_cbc_b64_decrypt((unsigned char *)mnemo, strlen(mnemo), &dec_len, PASSWORD_STAND);
            memset(mnemo, 0, strlen(mnemo));
            memcpy(mnemo, dec, dec_len);
            memset(dec, 0, dec_len);
            free(dec);							
        }
        //fill_report("debug sd read", mnemo, SUCCESS); // debug
        // TEST sd load
        if (mnemo) {
            wallet_master_from_mnemonic(mnemo, strlen(mnemo), salt, salt_len, 0);
        }
    } else {
        commander_fill_report("load", "A mnemonic or micro SD card filename not provided.", ERROR);
    }
}
			

static void process_seed(char *message)
{ 
    int salt_len;
    const char *salt = jsmn_get_value_string(message, CMD_STR[CMD_salt_], &salt_len);
    wallet_master_from_mnemonic(NULL, 0, salt, salt_len, jsmn_get_value_uint(message, CMD_STR[CMD_strength_]));
}


static void process_backup(char *message)
{ 
    int encrypt_len, filename_len;
    const char *encrypt = jsmn_get_value_string(message, CMD_STR[CMD_encrypt_], &encrypt_len);
    const char *filename = jsmn_get_value_string(message, CMD_STR[CMD_filename_], &filename_len);
	
	if (strcmp(message, ATTR_STR[ATTR_list_]) == 0) {
		sd_list();
		return;
	}
    
	if (!filename) {
        commander_fill_report("backup", "Incomplete command.", ERROR);
    } else {
        char *text = wallet_mnemonic_from_index(memory_mnemonic(NULL));
        if (!text) {
            commander_fill_report("backup", "BIP32 mnemonic not present.", ERROR);
            return;
        } 
        if (encrypt ? !strncmp(encrypt, "yes", 3) : 0) { // default = do not encrypt	
            int enc_len;
            char *enc = aes_cbc_b64_encrypt((unsigned char *)text, strlen(text), &enc_len, PASSWORD_STAND);
            if (enc) {
                sd_backup(filename, filename_len, enc, enc_len);
                if (memcmp(enc, sd_load(filename, filename_len), enc_len)) {
                    commander_fill_report("backup", "Corrupted file.", ERROR);
                }
                free(enc);
            } else {
                commander_fill_report("backup", "Could not allocate memory for encryption.", ERROR);
                return;
            }
        } else {
            sd_backup(filename, filename_len, text, strlen(text));  
            if (memcmp(text, sd_load(filename, filename_len), strlen(text))) {
                commander_fill_report("backup", "Corrupted file.", ERROR);
            }
        }
    }	
}


static void process_sign(char *message)
{ 
    int data_len, keypath_len, type_len, id_len, to_hash = 0;
    char *data, *keypath, *type, *id;
       
    id = (char *)jsmn_get_value_string(message, CMD_STR[CMD_id_], &id_len);
    type = (char *)jsmn_get_value_string(message, CMD_STR[CMD_type_], &type_len);
    data = (char *)jsmn_get_value_string(message, CMD_STR[CMD_data_], &data_len);
    keypath = (char *)jsmn_get_value_string(message, CMD_STR[CMD_keypath_], &keypath_len);
    
    if (!data || !keypath || !id || !type) {
        commander_fill_report("sign", "Incomplete command.", ERROR);
        return;  
    }
    if (strncmp(type, ATTR_STR[ATTR_raw_], strlen(ATTR_STR[ATTR_raw_])) == 0) {
        to_hash = 1;
    } else if (strncmp(type, ATTR_STR[ATTR_hash_], strlen(ATTR_STR[ATTR_hash_]))) {
        commander_fill_report("sign", "Unknown type value.", ERROR);
        return;
    }
    wallet_sign(data, data_len, keypath, to_hash, id, id_len);
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
        commander_fill_report("random", "Invalid command.", ERROR);
        return;
    }

    if (random_bytes(number, sizeof(number), update_seed)) {
        commander_fill_report("random", "Chip communication error.", ERROR);
    } else {
        commander_fill_report("random", uint8_to_hex(number, sizeof(number)), SUCCESS);
    }
}


static int process_password(const char *message, int msg_len, PASSWORD_ID id)
{
    return(memory_aeskey_write(message, msg_len, id));
}


static int commander_process_token(int cmd, char *message)
{
    switch (cmd) {
        case CMD_reset_:
            device_reset(message);
            return RESET;
        
        case CMD_password_:
		    if (process_password(message, strlen(message), PASSWORD_STAND) == SUCCESS) {
                commander_fill_report("password", "success", SUCCESS);
            }
            break;
        
        case CMD_multipass_:
		    if (process_password(message, strlen(message), PASSWORD_MULTI) == SUCCESS) {
                commander_fill_report("multipass", "success", SUCCESS);
            }
            break;
        
        case CMD_led_:
            if (strncmp(message, ATTR_STR[ATTR_toggle_], strlen(ATTR_STR[ATTR_toggle_])) == 0) {
                led_toggle(); delay_ms(300);	
                led_toggle();  
                commander_fill_report("led", "toggled", SUCCESS);
            } else {
                commander_fill_report("led", "Invalid command.", ERROR);
            }
            break;
        
        case CMD_name_:
            commander_fill_report("name", (char *)memory_name(message), SUCCESS);
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
        
        case CMD_random_:
            process_random(message);
            break;
      
        case CMD_xpub_:
            wallet_report_xpub(message);
            break;

        case CMD_touchbutton_:
            touch_button_parameters(jsmn_get_value_uint(message, CMD_STR[CMD_timeout_]) * 1000, 
                                    jsmn_get_value_uint(message, CMD_STR[CMD_threshold_]));
            break;

        case CMD_device_: {
            if (strcmp(message, ATTR_STR[ATTR_serial_]) == 0) {
				uint32_t serial[4];
				if (!flash_read_unique_id(serial, 16)) {
					commander_fill_report("serial", uint8_to_hex((uint8_t *)serial, sizeof(serial)), SUCCESS);         
				} else {
					commander_fill_report("serial", "Could not read flash.", ERROR);         
				}
			} else if (strcmp(message, ATTR_STR[ATTR_version_]) == 0) {
                commander_fill_report("version", (char *)DIGITAL_BITBOX_VERSION, SUCCESS);
            } else {
                commander_fill_report("device", "Invalid command.", ERROR);
            }
            break;
        }
        
        case CMD_none_:
            break;
    }
    return SUCCESS;
}


static char *commander_decrypt(const char *encrypted_command,  
                              jsmntok_t json_token[MAX_TOKENS],
                              int *n_tokens)
{
    // Process command
    char *command;
    int command_len, n = 0;
    
    // Decrypt & parse command
    command = aes_cbc_b64_decrypt((unsigned char*)encrypted_command, 
                                      strlen(encrypted_command), 
                                      &command_len,
                                      PASSWORD_STAND);
    
    if (command == NULL) {
        commander_fill_report("input", "Could not decrypt. "
                    "Too many access errors will cause the device to reset. ", ERROR);
        memory_delay_iterate(1);
    } else {
        memset(json_token, 0, sizeof(jsmntok_t) * MAX_TOKENS);
        n = jsmn_parse_init(command, command_len, json_token, MAX_TOKENS);
    }
    *n_tokens = n;
    
    if (!(json_token[0].type == JSMN_OBJECT  &&  n > 0))
    {
        commander_fill_report("input", "JSON parse error. "
                    "Too many access errors will cause the device to reset. "
                    "Is the command enclosed by curly brackets?", ERROR);
        memory_delay_iterate(1);
        return NULL;
    } else {
        return command;
    }
}


// Check if OK to process command.
static int commander_check_init(const char *encrypted_command)
{
	commander_clear_report();

    if (!encrypted_command) {
        commander_fill_report("input", "No input received. "
                    "Too many access errors will cause the device to reset.", ERROR);
        memory_delay_iterate(1);
        return ERROR;
    } 
    
    if (!strlen(encrypted_command)) {
        commander_fill_report("input", "No input received. "
                    "Too many access errors will cause the device to reset.", ERROR);
        memory_delay_iterate(1);
        return ERROR;
    }
    
    // In case of a forgotten password, allow reset from an unencrypted command.
    if (strstr(encrypted_command, CMD_STR[CMD_reset_]) != NULL) {
        int r_len;
        const char *r = jsmn_get_value_string(encrypted_command, CMD_STR[CMD_reset_], &r_len);
        device_reset(r);
        return ERROR;
	}
    
    // Force setting a password for encryption before processing command.
    if (memory_erased_read()) {		
        if (strstr(encrypted_command, CMD_STR[CMD_password_]) != NULL) {
            //memory_erase();
            //commander_clear_report();
            int pw_len;
            const char *pw = jsmn_get_value_string(encrypted_command, CMD_STR[CMD_password_], &pw_len);
            if (pw != NULL) {
                // For initialization, set both passwords to be the same. Then, the same code
                // is used independently of whether or not a multipass second password was set.
                // Add a multipass second password using a separate JSON command.
                if (process_password(pw, pw_len, PASSWORD_STAND) == SUCCESS && process_password(pw, pw_len, PASSWORD_MULTI) == SUCCESS) { 
                    memory_erased_write(0); 
                    commander_fill_report("password", "success", SUCCESS);
                }
            } else {
                commander_fill_report("input", "JSON parse error.", ERROR);
            }
        } else {
			commander_fill_report("input", "Please set a password.", ERROR);
		}
        return ERROR;
	}

    // Allow an unencrypted command to set a multipass second password (first time only)
    // A multipass password reset is done via an encrypted JSON command, or here after a device reset
    if (memory_multipass_read()) {
        if (strstr(encrypted_command, CMD_STR[CMD_multipass_]) != NULL) {
	        commander_clear_report();
            int pw_len;
            const char *pw = jsmn_get_value_string(encrypted_command, CMD_STR[CMD_multipass_], &pw_len);
            if (pw != NULL) {
                if (!touch_button_press(0)) {
                    if (process_password(pw, pw_len, PASSWORD_MULTI) == SUCCESS) { 
                        memory_multipass_write(0); 
                        commander_fill_report("multipass", "success", SUCCESS);
                    }
                }
            } else {
                commander_fill_report("input", "JSON parse error.", ERROR);
            }
            return ERROR;
        }
    }
    
    return SUCCESS; 
}
 

// Echo the signing information for user verification.
static void commander_echo(const char *command)
{
    commander_clear_report();
    
    // Encrypt the echo with multipass password
    int encrypt_len;
    char *encoded_report = aes_cbc_b64_encrypt((unsigned char *)command,
                                            strlen(command), 
                                            &encrypt_len,
                                            PASSWORD_MULTI); 
    // Fill report to send
    commander_clear_report();
    if (encoded_report) {
        commander_fill_report_len("echo", encoded_report, SUCCESS, encrypt_len);
        free(encoded_report);
    } else {
        commander_fill_report("output", "Could not allocate memory for encryption.", ERROR);
    }    
}
                        

static char *commander_format_output(const char *output) 
{
    static char out[COMMANDER_REPORT_SIZE];
    memset(out, 0, COMMANDER_REPORT_SIZE);
    strcat(out, "{\"serialized_outputs\":\"");
    strncat(out, output, strlen(output));
    strcat(out, "\"}");
    return out;
}


// Returns 0 if inputs and outputs are the same
static int commander_verify_signing(const char *message)
{
    int data_len, type_len;
    char *data, *type;
    
    type = (char *)jsmn_get_value_string(message, CMD_STR[CMD_type_], &type_len);
    data = (char *)jsmn_get_value_string(message, CMD_STR[CMD_data_], &data_len);
   
    if (!data || !type) {
        commander_fill_report("sign", "Incomplete command.", ERROR);
        return ERROR;  
    }
    
    if (strncmp(type, ATTR_STR[ATTR_raw_], strlen(ATTR_STR[ATTR_raw_])) == 0) 
    {
        // Check if deserialized inputs and outputs are the same (scriptSig's could be different)
        // Updates verify_input and verify_output
        if (wallet_check_input_output(data, data_len, verify_input, verify_output) == SAME){
            return SAME;
        } else {
            commander_echo(commander_format_output(verify_output)); 
            return DIFFERENT;
        }
    } 
    else 
    {
        // Check whole input command instead of inputs/outputs since data is hashed
        if (memcmp(verify_output, message, strlen(message))) {
            // Different command received, reset
            memset(verify_output, 0, COMMANDER_REPORT_SIZE);
            memcpy(verify_output, message, strlen(message));
            commander_echo(verify_output); 
            return DIFFERENT;
        } else {
            // Same command received
            return SAME;
        }
    }
}


static int commander_touch_button(int found_cmd, const char *message)
{
    int t, c, ret;
    
    if (found_cmd == CMD_sign_) {
        c = commander_verify_signing(message);
        if (c == SAME) {
            t = touch_button_press(1);
            if (t == NOT_TOUCHED) {
                // Clear previous signing information
                // to force touch for next sign command.
                memset(verify_input, 0, COMMANDER_REPORT_SIZE);
                memset(verify_output, 0, COMMANDER_REPORT_SIZE);
            }
            ret = t;
        } else if (c == DIFFERENT) {
            ret = ECHO; 
        } else {
            ret = ERROR;
        }
        
    } else if (found_cmd < CMD_require_touch_) {
        ret = touch_button_press(0);

    } else {
        ret = TOUCHED;
    }
    
    return ret;
}


// Parse and process command
static void commander_parse(const char *encrypted_command)
{ 
    //printf("\n\nCommand:\t%lu %s\n", strlen(encrypted_command), encrypted_command);		
    
    int n_tokens, j, t, cmd, found, found_cmd, found_j, msglen;
    jsmntok_t json_token[MAX_TOKENS];

    commander_clear_report();
    
    char *command = commander_decrypt(encrypted_command, json_token, &n_tokens);
    if (!command) {
        return;
    }
    
    // Extract commands
    found = 0;
    for (j = 0; j < n_tokens; j++) {
        if (json_token[j].parent != 0) {
            continue; // Skip child tokens
        }
        for (cmd = 0; cmd < CMD_NUM; cmd++) {    
            if (jsmn_token_equals(command, &json_token[j], CMD_STR[cmd]) == 0) 
            {                    
                found++;
                found_j = j;
                found_cmd = cmd;
                break;
            }
        }
    }

    // Process commands
    if (!found) {
        commander_fill_report("input", "A valid command was not found.", ERROR);
    } else if (found > 1) {
        commander_fill_report("input", "Only one command allowed at a time.", ERROR);
    } else {
        memory_delay_iterate(0); // reset to 0
        msglen = json_token[found_j + 1].end-json_token[found_j + 1].start;
        char message[msglen + 1];
        memcpy(message, command + json_token[found_j + 1].start, msglen);
        message[msglen] = '\0';
        t = commander_touch_button(found_cmd, message);
        if (t == ECHO) {
            return;
        } else if (t == TOUCHED) {
            if (commander_process_token(found_cmd, message) == RESET) {
                free(command);
                return;
            }
            memset(message, 0, msglen);
        } else {
            // error or not touched
        }
    }

    // Encrypt report
    int encrypt_len;
    char *encoded_report = aes_cbc_b64_encrypt((unsigned char *)json_report,
                                            strlen(json_report), 
                                            &encrypt_len,
                                            PASSWORD_STAND); // encrypt output with the opposite password used to encrypt input`
    
    // Fill encrypted JSON report to send
    commander_clear_report();
    if (encoded_report) {
        commander_fill_report_len("ciphertext", encoded_report, SUCCESS, encrypt_len);
        free(encoded_report);
    } else {
        commander_fill_report("output", "Could not allocate memory for encryption.", ERROR);
    }
    
    memset(command, 0, strlen(command));
    free(command);
    memory_clear_variables();
}


// Single gateway function to the MCU code
char *commander(const char *command)
{
    if (commander_check_init(command) == SUCCESS) {
        commander_parse(command);
    }
	return json_report;
}


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
    aes_set_key(memory_aeskey_read(id), 32, ctx); 
    
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


char *aes_cbc_b64_decrypt(const unsigned char *in, int inlen, int *decrypt_len, PASSWORD_ID id)
{
    // unbase64
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
    aes_set_key(memory_aeskey_read(id), 32, ctx); 
    
    unsigned char dec_pad[ub64len - N_BLOCK];
    aes_cbc_decrypt(ub64 + N_BLOCK, dec_pad, ub64len / N_BLOCK - 1, ub64, ctx);
    memset(ub64, 0, ub64len);
    free(ub64);
  
    // Strip PKCS7 padding
    int padlen = dec_pad[ub64len - N_BLOCK - 1];
    char *dec = malloc(ub64len - N_BLOCK - padlen + 1); // +1 for null termination
    if (!dec)
    {
        commander_fill_report("input", "Could not allocate memory for decryption.", ERROR);
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





