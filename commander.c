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
#include "aes.h"
#include "led.h"
#include "sd.h"
#ifndef NOT_EMBEDDED
#include <asf.h>
#include "ataes132.h"
#else
void delay_ms( int delay ){ (void)delay; }
#endif

const char * CMD_STR[] = { FOREACH_CMD(GENERATE_STRING) };
const char * ATTR_STR[] = { FOREACH_ATTR(GENERATE_STRING) };

// JSMN.C extension
jsmnerr_t jsmn_parse_init(const char *js, size_t len,
		jsmntok_t *tokens, unsigned int num_tokens){
	jsmn_parser p;
	jsmn_init(&p);
	return( jsmn_parse(&p, js, len, tokens, num_tokens) );
}

static const char * jsmn_get_string(const char * message, int cmd, int report, int * len)
{
	int r, i;
	*len = 0;
	jsmntok_t json_token[MAX_TOKENS];
	r = jsmn_parse_init(message, strlen(message), json_token, MAX_TOKENS);
	if (r < 0) {
		if( report ){ fill_report("input","JSON parse error.",ERROR); }
		return 0;
	}	
	for (i = 0; i < r; i++) {
		if (token_equals(message, &json_token[i], CMD_STR[cmd]) == 0 ) {
			*len = json_token[i+1].end-json_token[i+1].start;
			return(message+json_token[i+1].start);
		}
	}
	if( report ){ fill_report("input","JSON parse error.",ERROR); }
	return 0;
}

static uint16_t jsmn_get_uint16_t(const char * message, int cmd)
{
    int r, i;
    jsmntok_t json_token[MAX_TOKENS];
    r = jsmn_parse_init(message, strlen(message), json_token, MAX_TOKENS);
     
    if (r < 0) {
        fill_report("input","JSON parse error.",ERROR);
    }
    for (i = 0; i < r; i++) {
        if (token_equals(message, &json_token[i], CMD_STR[cmd]) == 0 ) {
            int vallen = json_token[i+1].end-json_token[i+1].start;
            char val[vallen+1];
            memcpy( val, message + json_token[i+1].start, vallen );
            val[vallen] = '\0';
            unsigned int valu = 0;
			if( vallen ){ sscanf(val,"%u", &valu); }
            return valu;  
        }
    }
    return 0;
}

int token_equals(const char *json, const jsmntok_t *tok, const char *s) {
	if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
			strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}



static int REPORT_BUF_OVERFLOW = 0;
static int BUTTON_TOUCHED = 0;

// TODO use msg and error codes to pass to fill_report?
void fill_report(const char * attr, const char * val, int err)
{
	fill_report_len(attr,val,err,strlen(val));
}

void fill_report_len(const char * attr, const char * val, int err, int vallen)
{
    size_t len = strlen(hid_report);
    if( len==0 ){
        strncat(hid_report,"{",1);
    }else {    
        hid_report[len-1] = ','; // replace closing '}' with ','
    }

    if( len > (HID_REPORT_SIZE - ( 21+strlen(attr)+strlen(val) )) || len > (HID_REPORT_SIZE - 128) ){
        // TEST the overflow error
        if( !REPORT_BUF_OVERFLOW )  
        {
            strcat(hid_report,"{ \"output\":{ \"error\":\"Buffer overflow.\"} }");
            REPORT_BUF_OVERFLOW = 1;
        }
    }else {
        strcat(hid_report," \"");
        strcat(hid_report,attr);
        if( err == ERROR ){ strcat(hid_report,"\":{ \"error\":\""); }
        else{               strcat(hid_report,"\":\""); }
        strncat(hid_report,val,vallen); 
		if( err == ERROR ){ strcat(hid_report,"\" } }"); }
        else{               strcat(hid_report,"\" }"); }
    }
}

void device_reset( const char * r )
{
    if( r ){ 
        if( strncmp(r, ATTR_STR[ATTR___ERASE___],strlen(ATTR_STR[ATTR___ERASE___])) == 0 ){ 
            led_state("enable");
			led_on();
            if (touch_button_press()) { delay_ms(1500);
            if (touch_button_press()) { delay_ms(1500);
            if (touch_button_press()) {
                memory_erase();
				memset(hid_report,0,HID_REPORT_SIZE);
                fill_report("reset","success",SUCCESS);
            }}}
        }
        else{
		    fill_report("reset","Incorrect syntax.",ERROR);
        }
    }
}

static int commander_process_token(int cmd, char * message)
{
    switch( cmd ){
        case CMD_reset_ : {
            device_reset(message);
            return -1;
        }
        
        case CMD_password_ : {
		    memory_aeskey_write(message, strlen(message));
            break;
        }
       
        case CMD_load_ : {
			int wallet_len, mnemonic_len, sd_file_len, salt_len, decrypt_len;
			const char * mnemonic = jsmn_get_string( message, CMD_mnemonic_, SUPPRESS, &mnemonic_len );
			const char * sd_file = jsmn_get_string( message, CMD_sd_file_, SUPPRESS, &sd_file_len );
			const char * decrypt = jsmn_get_string( message, CMD_decrypt_, SUPPRESS, &decrypt_len );
			const char * wallet = jsmn_get_string( message, CMD_wallet_, SUPPRESS, &wallet_len );
			const char * salt = jsmn_get_string( message, CMD_salt_, SUPPRESS, &salt_len );
            if( wallet ){
	            if( !BUTTON_TOUCHED ){
		            if( touch_button_press()) { BUTTON_TOUCHED = 1; }
	            }
	            if( BUTTON_TOUCHED ){
					if( mnemonic ){
						if( strncmp(wallet, ATTR_STR[ATTR_electrum_],strlen(ATTR_STR[ATTR_electrum_])) == 0 ){
							master_from_mnemonic_electrum( mnemonic, mnemonic_len );
						}
						else if( strncmp(wallet, ATTR_STR[ATTR_bip32_],strlen(ATTR_STR[ATTR_bip32_])) == 0 ){
							master_from_mnemonic_bip32( (char *)mnemonic, mnemonic_len, salt, salt_len, 0 );
						} 
					}
					else if( sd_file ){
						char * mnemo = load_sd(sd_file, sd_file_len);
						if( decrypt ? strncmp(decrypt, "no", 2) : 1 ){ // default = decrypt
							int dec_len;
							char * dec = aes_cbc_b64_decrypt( (unsigned char *)mnemo, strlen(mnemo), memory_aeskey_read(), &dec_len );
							memset(mnemo,0,strlen(mnemo));
							memcpy(mnemo,dec,dec_len);
							free( dec );							
						}
						//fill_report("debug sd read",mnemo,SUCCESS); // debug

						if( mnemo ){
							if( strncmp(wallet, ATTR_STR[ATTR_electrum_],strlen(ATTR_STR[ATTR_electrum_])) == 0 ){
								master_from_mnemonic_electrum( mnemo, strlen(mnemo) );
							}
							else if( strncmp(wallet, ATTR_STR[ATTR_bip32_],strlen(ATTR_STR[ATTR_bip32_])) == 0 ){
								master_from_mnemonic_bip32( mnemo, strlen(mnemo), salt, salt_len, 0 );
							}
						}
					}
					else{
						fill_report("load","A mnemonic or micro SD card filename not provided.",ERROR);
					}   
			}   }
            else {
                fill_report("load","Invalid command.",ERROR);
            }
            break; 
        }
        
        case CMD_seed_ : {
			int wallet_len, salt_len;
			const char * wallet = jsmn_get_string( message, CMD_wallet_, SUPPRESS, &wallet_len );
			const char * salt = jsmn_get_string( message, CMD_salt_, SUPPRESS, &salt_len );
            if( wallet ){
	            if( !BUTTON_TOUCHED ){
		            if( touch_button_press()) { BUTTON_TOUCHED = 1; }
	            }
	            if( BUTTON_TOUCHED ){
					if( strncmp(wallet, ATTR_STR[ATTR_electrum_],strlen(ATTR_STR[ATTR_electrum_])) == 0 ){
						master_from_mnemonic_electrum( NULL, 0 );
					}
					else if( strncmp(wallet, ATTR_STR[ATTR_bip32_],strlen(ATTR_STR[ATTR_bip32_])) == 0 ){
						master_from_mnemonic_bip32( NULL, 0, salt, salt_len, jsmn_get_uint16_t(message,CMD_strength_) );
					}
				}
            }
            else {
                fill_report("seed","Invalid command.",ERROR);
            }
            break;
        }
        
        case CMD_backup_ : {		
			int wallet_len, encrypt_len, format_len, filename_len;
			const char * wallet = jsmn_get_string( message, CMD_wallet_, SUPPRESS, &wallet_len );
            const char * format = jsmn_get_string( message, CMD_format_sd_card_, SUPPRESS, &format_len );
            const char * encrypt = jsmn_get_string( message, CMD_encrypt_, SUPPRESS, &encrypt_len );
            const char * filename = jsmn_get_string( message, CMD_filename_, SUPPRESS, &filename_len );
            if( format ? !strncmp(format, "yes", 3) : 0 ){ // default = do not format
                if( !BUTTON_TOUCHED ){
                    if( touch_button_press()) { BUTTON_TOUCHED = 1; }
                }
                if( BUTTON_TOUCHED ){
					if( format_sd() ){
						break; // could not format
					}
                }
				else{
					break; // button not touched
				}
            }
            if( !filename || !wallet ){
				if( !(format && !filename && !wallet) ){
	                fill_report("backup","Incomplete command.",ERROR);
				}
	        }
            else{
                if( !BUTTON_TOUCHED ){
                    if( touch_button_press()) { BUTTON_TOUCHED = 1; }
                }
                if( BUTTON_TOUCHED ){
                    if( strncmp(wallet, ATTR_STR[ATTR_electrum_], strlen(ATTR_STR[ATTR_electrum_])) == 0 ){
                        char * text = mnemonic_from_seed_electrum( memory_electrum_mnemonic(NULL) );
                        if( !text ){
                            fill_report("backup","Electrum mnemonic not present.",ERROR);
                        }
                        else if( encrypt ? strncmp(encrypt, "no", 2) : 1 ){ // default = encrypt
                            int enc_len;
                            char * enc = aes_cbc_b64_encrypt( (unsigned char *)text, strlen(text), memory_aeskey_read(), &enc_len );
                            backup_sd(filename, filename_len, enc, enc_len);
                            free( enc );
                        }
                        else{
                            backup_sd(filename, filename_len, text, strlen(text));  
                        }
                    }
                    else if( strncmp(wallet, ATTR_STR[ATTR_bip32_], strlen(ATTR_STR[ATTR_bip32_])) == 0 ){
                        char * text = mnemonic_from_index_bip32( memory_bip32_mnemonic(NULL) ); // TEST
                        if( !text ){
                            fill_report("backup","BIP32 mnemonic not present.",ERROR);
                        }
						else if( encrypt ? strncmp(encrypt, "no", 2) : 1 ){ // default = encrypt	
	                        int enc_len;
                            char * enc = aes_cbc_b64_encrypt( (unsigned char *)text, strlen(text), memory_aeskey_read(), &enc_len );
                            backup_sd(filename, filename_len, enc, enc_len);
                            free( enc );
                        }
                        else{
                            backup_sd(filename, filename_len, text, strlen(text));  
                        }
                    }
                }
            }	
            break;
        }
        
        case CMD_master_public_key_ : {
            if( strcmp(message, ATTR_STR[ATTR_electrum_]) == 0 ){
                report_master_public_key_electrum();
	        }
            else if( strcmp(message, ATTR_STR[ATTR_bip32_]) == 0 ){
                report_master_public_key_bip32();
            }
            else {
                fill_report("master_public_key","Invalid command.",ERROR);
            }
            break;
        }
                
        case CMD_sign_ : {
			int wallet_len, tx_len, keypath_len, encoding_len;		
			const char * wallet = jsmn_get_string(message,CMD_wallet_, SUPPRESS,&wallet_len);
			const char * tx = jsmn_get_string(message,CMD_message_, SUPPRESS,&tx_len);
			const char * keypath = jsmn_get_string(message,CMD_keypath_, SUPPRESS,&keypath_len);
			const char * encoding = jsmn_get_string(message,CMD_encoding_, SUPPRESS,&encoding_len);
			
            int enc;
            int err = 0;
            if( !wallet || !tx || !encoding || !keypath ){
                fill_report("sign","Incomplete command.",ERROR);
                err = 1; 
            }
            else if( strncmp(encoding, ATTR_STR[ATTR_der_], strlen(ATTR_STR[ATTR_der_])) == 0 ){ enc = ATTR_der_; }
            else if( strncmp(encoding, ATTR_STR[ATTR_message_], strlen(ATTR_STR[ATTR_message_])) == 0 ){ enc = ATTR_message_; }
            else if( strncmp(encoding, ATTR_STR[ATTR_none_], strlen(ATTR_STR[ATTR_none_])) == 0 ){ enc = ATTR_none_; }
            else{ 
                fill_report("sign","Invalid encoding method.",ERROR); 
                err = 1;
            }
           
            if( !err ) { 
                if( !BUTTON_TOUCHED ){
                    if( touch_button_press()) { BUTTON_TOUCHED = 1; }
                }
                if( BUTTON_TOUCHED ){
                    if( strncmp(wallet, ATTR_STR[ATTR_electrum_], strlen(ATTR_STR[ATTR_electrum_])) == 0 ){
                        sign_electrum(tx,(char *)keypath,enc);
	                }
                    else if( strncmp(wallet, ATTR_STR[ATTR_bip32_], strlen(ATTR_STR[ATTR_bip32_])) == 0 ){
                        sign_bip32(tx,(char *)keypath,enc);
                    }
                    else {
                        fill_report("sign","Invalid wallet type.",ERROR);
                    }
                }
            }
            break;
        }
        
        case CMD_led_ : {
		    fill_report("led",(char *)led_state(message),SUCCESS);
            break;
        }
        
        case CMD_name_ : {
            fill_report("name",(char *)memory_name(message),SUCCESS);
            break;
        }
        
        case CMD_touchbutton_ : {
		    // TEST disable function
            int status_len;
            const char * status = jsmn_get_string(message,CMD_button_, SUPPRESS, &status_len);
            int s = -1; 
            if( status ){
                if( strncmp(status, ATTR_STR[ATTR_disable_],strlen(ATTR_STR[ATTR_disable_])) == 0 ){ s = 0; }
                else if( strncmp(status, ATTR_STR[ATTR_enable_],strlen(ATTR_STR[ATTR_enable_])) == 0 ){ s = 1; }
			}
            touch_button_parameters(jsmn_get_uint16_t(message,CMD_timeout_), jsmn_get_uint16_t(message,CMD_threshold_), s);
            break;
        }

        case CMD_device_ : {
            if( strcmp(message, ATTR_STR[ATTR_serial_]) == 0 ){
	            fill_report("serial","...",SUCCESS); // TODO get serial number
            }
            else if( strcmp(message, ATTR_STR[ATTR_version_]) == 0 ){
                fill_report("version",(char *)DIGITAL_BITBOX_VERSION,SUCCESS);
            }
            else {
                fill_report("device","Invalid command.",ERROR);
            }
            break;
        }
        
        case CMD_random_ : {
            // TEST
            int update_seed;
            uint8_t number[16];
            if( strcmp(message, ATTR_STR[ATTR_true_]) == 0 ){
                update_seed = 1;
            }
            else if( strcmp(message, ATTR_STR[ATTR_pseudo_]) == 0 ){
                update_seed = 0;
            }
            else {
                fill_report("random","Invalid command.",ERROR);
                break; 
            }

            if( random_bytes(number, sizeof(number), update_seed) ){
                fill_report("random","Chip communication error.",ERROR);
            }else{
                fill_report("random",uint8_to_hex(number,sizeof(number)),SUCCESS);
            }
            break;
        }
        
        
        
        case CMD_none_ :
            break;
    }
    return 0;
}

char * commander(const char *instruction_encrypted)
{
    //printf("Command:\t%lu %s\n",strlen(instruction_encrypted),instruction_encrypted);
    memset(hid_report,0,HID_REPORT_SIZE);
    REPORT_BUF_OVERFLOW = 0;
    BUTTON_TOUCHED = 0;
    led_on();

    if( !instruction_encrypted ){
        fill_report("input","A valid command was not found.",ERROR);
    }
    else if( !strlen(instruction_encrypted) ){
        fill_report("input","A valid command was not found.",ERROR);
    }
    
    // In case of forgotten password, allow reset from unencrypted command.
    else if( strstr(instruction_encrypted, CMD_STR[CMD_reset_]) != NULL )
	{
        int r_len;
        const char * r = jsmn_get_string(instruction_encrypted,CMD_reset_, REPORT, &r_len);
        device_reset(r);
	}
    
    // Force setting a password before allowing commands to be processed.
    else if( memory_erased_read() )
	{		
        if( strstr(instruction_encrypted, CMD_STR[CMD_password_]) != NULL ){
            memory_erase();
            memset(hid_report,0,HID_REPORT_SIZE);
            int pw_len;
            const char * pw = jsmn_get_string(instruction_encrypted,CMD_password_, REPORT, &pw_len);
            if( pw != NULL ){
                if( memory_aeskey_write(pw, pw_len) ){ memory_erased_write(0); }
            } 
        }
		else
		{
			fill_report("input","Please set a password.",ERROR);
		}
	}
	
    // Process commands.
    else
	{
        // Decrypt instructions
        int instruction_len;
		char * instruction = aes_cbc_b64_decrypt( (unsigned char*)instruction_encrypted, strlen(instruction_encrypted), memory_aeskey_read(), &instruction_len );
        
        // Parse commands
	    if( instruction ){
            int r, i, cmd, found, msglen;
            jsmntok_t json_token[MAX_TOKENS];
            r = jsmn_parse_init(instruction, strlen(instruction), json_token, MAX_TOKENS);
            if( json_token[0].type != JSMN_OBJECT  ||  r < 0 ) 
            {
                fill_report("input","JSON parse error. Is the command enclosed by curly brackets?",ERROR);
            }
            else
            {
                found = 0;
                for (i = 0; i < r; i++) {
                    if (json_token[i].parent != 0)
                    {
                        continue; // skip child tokens
                    }
                    for (cmd = 0; cmd < CMD_NUM; cmd++) {    
                        if (token_equals(instruction, &json_token[i], CMD_STR[cmd]) == 0) {
                            found = 1;
                            msglen = json_token[i+1].end-json_token[i+1].start;
                            char message[msglen+1];
                            memcpy( message, instruction + json_token[i+1].start, msglen );
                            message[msglen] = '\0';
                            if( commander_process_token(cmd, message) < 0 ){
                                free( instruction );
                                return hid_report; // _reset_ called
                            }
                            break;
                        }
                    }
                }
                if( !found ){
                    fill_report("input","A valid command was not found.",ERROR);
                }
            }
    	}

		// Encrypt report
		int encrypt_len;
		char * encoded_report = aes_cbc_b64_encrypt( (unsigned char *)hid_report, strlen(hid_report), memory_aeskey_read(), &encrypt_len );
		memset(hid_report,0,HID_REPORT_SIZE);
        fill_report_len("ciphertext",encoded_report,SUCCESS,encrypt_len);
        free( encoded_report );
		
        free( instruction );
	}
	delay_ms(100);
	led_off();
	return hid_report;
}



// AES.C extensions
// Must free() returned value (allocated inside base64() function)
char * aes_cbc_b64_encrypt( const unsigned char *in, int inlen, const uint8_t key[MEM_PAGE_LEN], int *out_b64len ){

    // Set cipher key
    aes_context ctx[1]; 
    memset(ctx,0,sizeof(ctx));  
    aes_set_key( key, MEM_PAGE_LEN, ctx ); 
    
    // PKCS7 padding
    int  pads;
    int  inpadlen = inlen + N_BLOCK - inlen%N_BLOCK;
    unsigned char inpad[inpadlen];
    memcpy(inpad,in,inlen);
    for( pads=0 ; pads<N_BLOCK-inlen%N_BLOCK ; pads++ ){
        inpad[inlen+pads] = (N_BLOCK-inlen%N_BLOCK);
    }
    
    unsigned char enc[inpadlen];
    unsigned char iv[N_BLOCK];
    unsigned char enc_cat[inpadlen+N_BLOCK]; // concatenating [ iv0  |  enc ]
    
    // Make a random initialization vector 
    random_bytes((uint8_t *)iv, N_BLOCK, 0); 
    memcpy(enc_cat,iv,N_BLOCK);
    
    // CBC encrypt multiple blocks
    aes_cbc_encrypt( inpad, enc, inpadlen/N_BLOCK, iv, ctx );
    memcpy(enc_cat+N_BLOCK,enc,inpadlen);

    // base64 encoding      
    int b64len;
    char * b64;
    b64 = base64( enc_cat, inpadlen+N_BLOCK, &b64len );
    
    *out_b64len = b64len;
    return b64;
}


char * aes_cbc_b64_decrypt( const unsigned char *in, int inlen, const uint8_t key[MEM_PAGE_LEN], int *decrypt_len )
{
    // Set cipher key
    aes_context ctx[1]; 
    memset(ctx,0,sizeof(ctx));  
    aes_set_key( key, MEM_PAGE_LEN, ctx ); 
    
    // unbase64
    int ub64len;
    unsigned char * ub64 = unbase64( (char *)in, inlen, &ub64len );
    if( ub64len % N_BLOCK ){
        fill_report("input","Invalid encryption.",ERROR);
        decrypt_len = 0;
        free( ub64 );
        return NULL;
    }
    
    unsigned char dec_pad[ub64len-N_BLOCK];
    aes_cbc_decrypt( ub64+N_BLOCK, dec_pad, ub64len/N_BLOCK - 1, ub64, ctx ); // CBC decrypt multiple blocks
    free( ub64 );
  
    // Strip PKCS7 padding
    int padlen = dec_pad[ub64len-N_BLOCK-1];
    char * dec = malloc( ub64len-N_BLOCK-padlen + 1 ) ; // +1 for null termination
    if( !dec )
    {
        fill_report("input","Could not allocate enough memory for decryption.",ERROR);
        decrypt_len = 0;
        return NULL;
    }
    memcpy(dec,dec_pad,ub64len-N_BLOCK-padlen);
    dec[ub64len-N_BLOCK-padlen] = '\0';

    *decrypt_len = ub64len-N_BLOCK-padlen+1;
    return dec;    
}





