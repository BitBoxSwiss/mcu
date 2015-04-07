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


#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tests_internal.h"
#include "commander.h"
#include "wallet.h"
#include "random.h"
#include "flags.h"
#include "utils.h"
#include "uECC.h"

#ifdef TESTING
#include "sham.h"
#else
#include "systick.h"
#include "mcu.h"

extern volatile uint16_t systick_current_time_ms;
#endif

extern const uint8_t MEM_PAGE_ERASE[MEM_PAGE_LEN];

static char tests_report[COMMANDER_REPORT_SIZE] = {0};

void tests_fill_report(const char *attr, const char *val)
{
    
    int vallen = strlen(val);
    size_t len = strlen(tests_report);
    if (len == 0) {
        strncat(tests_report, "{", 1);
    } else {    
        tests_report[len - 1] = ','; // replace closing '}' with continuing ','
    }

    strcat(tests_report, " \"");
    strcat(tests_report, attr);
    strcat(tests_report, "\":\""); 
    strncat(tests_report, val, vallen); 
    
    // Add closing '}'
    strcat(tests_report, "\" }"); 
}


static int tests_sign_speed(void)
{
	// N = 50 -> 7.5 sig/sec
	uint8_t sig[64], priv_key_0[32], priv_key_1[32], msg[256];
	uint16_t time_ms;
	size_t i, N = 50; 
	int res;
	for (i = 0; i < sizeof(msg); i++) {
		msg[i] = i * 1103515245;
	}

	memcpy(priv_key_0, hex_to_uint8("c55ece858b0ddd5263f96810fe14437cd3b5e1fbd7c6a2ec1e031f05e86d8bd5"), 32);
	memcpy(priv_key_1, hex_to_uint8("509a0382ff5da48e402967a671bdcde70046d07f0df52cff12e8e3883b426a0a"), 32);

#ifdef TESTING
    clock_t t = clock();
#else
	NVIC_SetPriority(SysTick_IRQn, 0); // Make high priority so that we can timeout
	systick_current_time_ms = 0;
#endif
	
	for (i = 0 ; i < N; i++) {
		res = uECC_sign(priv_key_0, msg, sizeof(msg), sig);
	}

	for (i = 0 ; i < N; i++) {
		res += uECC_sign(priv_key_1, msg, sizeof(msg), sig);
	}

#ifdef TESTING
	time_ms = (float)(clock() - t) * 1000 / CLOCKS_PER_SEC;
#else
    time_ms = systick_current_time_ms;
	NVIC_SetPriority(SysTick_IRQn, 15); // Reset lower priority
#endif
	
    if (res) {
		tests_fill_report("tests_sign_speed", "FAIL - Could not sign");
	} else {
		char report[64];
		sprintf(report, "%0.2f sig/s", N * 2 / ((float)time_ms / 1000));
		tests_fill_report("tests_sign_speed", report);
	}
	
    return SUCCESS;
}


static void tests_backup_erase(void)
{
    char *pw = "0000";
    commander_force_reset();
    memory_write_aeskey(pw, strlen(pw), PASSWORD_STAND);
    sd_erase();
}


static int tests_backup(void)
{
    char *m, mnemo[256] = {0}, xpub0[112] = {'0'}, xpub1[112] = {'1'};
    char *filename = "tests_backup.txt";
    char *keypath = "m/44\'/0\'/";
	
    const char **salt, **cipher;
	static const char *options[] = {
		// salt           encrypt
		"Digital Bitbox", "no", 
		"Digital Bitbox", "yes", 
		"",               "no", 
		"",               "yes", 
		0, 0,
	};
	salt = options;
	cipher = options + 1;
    
	while (*salt && *cipher) {
        
        // Create new wallet and backup to SD card
        tests_backup_erase();
        if (wallet_master_from_mnemonic(NULL, 0, *salt, strlen(*salt)) != SUCCESS) {
            goto err;
        }
        wallet_report_xpub(keypath, strlen(keypath), xpub0);
        m = wallet_mnemonic_from_index(memory_mnemonic(NULL));
        memset(mnemo, 0, sizeof(mnemo));
        if (m) { memcpy(mnemo, m, strlen(m)); }
        if (!strncmp(*cipher, "yes", 3)) { // default = do not encrypt	
            int enc_len;
            char *enc = aes_cbc_b64_encrypt((unsigned char *)mnemo, strlen(mnemo), &enc_len, PASSWORD_STAND);
            if (enc) {
                if (sd_write(filename, strlen(filename), enc, enc_len) != SUCCESS) {
                    free(enc);
                    goto err;
                }
                free(enc);
            }
        } else {
            if (sd_write(filename, strlen(filename), mnemo, strlen(mnemo)) != SUCCESS) {
                goto err;
            }
        }
        
        // Reload from SD card
        tests_backup_erase();
        m = sd_load(filename, strlen(filename));
        memset(mnemo, 0, sizeof(mnemo));
        if (m) { memcpy(mnemo, m, strlen(m)); }
        if (m && !strncmp(*cipher, "yes", 3)) { // default = do not decrypt
            int dec_len;
            char *dec = aes_cbc_b64_decrypt((unsigned char *)mnemo, strlen(mnemo), &dec_len, PASSWORD_STAND);
            memset(mnemo, 0, sizeof(mnemo));
            memcpy(mnemo, dec, dec_len);
            memset(dec, 0, dec_len);
            free(dec);
        }
        wallet_master_from_mnemonic(mnemo, strlen(mnemo), *salt, strlen(*salt));
        wallet_report_xpub(keypath, strlen(keypath), xpub1);
        
        // Compare master xpubs for original and reloaded wallets
        if(memcmp(xpub0, xpub1, 112)) {
            goto err;
        }
        
        salt += 2;
        cipher += 2;
    }
            
    tests_fill_report("tests_backup", "OK");
    return SUCCESS;

    err:
        tests_fill_report("tests_backup", "FAIL");
        return ERROR;
}


static int tests_reset(void)
{
    char *pw = "0000";

    // Create new wallet
    commander_force_reset();
    memory_write_aeskey(pw, strlen(pw), PASSWORD_STAND);
    
    if (wallet_master_from_mnemonic(NULL, 0, NULL, 0) != SUCCESS) {
        tests_fill_report("tests_reset", "FAIL - Could not create wallet.");
        return ERROR;
    }
    if (!memcmp(memory_master(NULL), MEM_PAGE_ERASE, 32)) {
        tests_fill_report("tests_reset", "FAIL - Master not set.");
        return ERROR;
    }
    
    // Reset
    commander_force_reset();
    
    if (memcmp(memory_master(NULL), MEM_PAGE_ERASE, 32)) {
        tests_fill_report("tests_reset", "FAIL - Master still set");
        return ERROR;
    }

    tests_fill_report("tests_reset", "OK");
    return SUCCESS;
}


static int tests_random(void)
{
    int update_seed = 0;
    uint8_t number0[16];
    uint8_t number1[16];

    if (random_bytes(number0, sizeof(number0), update_seed)) {
        tests_fill_report("tests_random", "FAIL - ATAES error");
        return ERROR;
    } 
    
    if (random_bytes(number1, sizeof(number1), update_seed)) {
        tests_fill_report("tests_random", "FAIL - ATAES error");
        return ERROR;
    } 
   
    if (!memcmp(number0, number1, 16)) {
        tests_fill_report("tests_random", "FAIL - Same number");
        return ERROR;
    }
    
    tests_fill_report("tests_random", "OK");
    return SUCCESS;
}


static int tests_name(void)
{
    char *name0 = "name0";
    char *name1 = "name1";
   
    if (memcmp(name0, (char *)memory_name(name0), strlen(name0))) {
        tests_fill_report("tests_name", "FAIL");
        return ERROR;
    }
    
    if (memcmp(name1, (char *)memory_name(name1), strlen(name1))) {
        tests_fill_report("tests_name", "FAIL");
        return ERROR;
    }
    
    if (!memcmp(name0, (char *)memory_name(name1), strlen(name0))) {
        tests_fill_report("tests_name", "FAIL");
        return ERROR;
    }
    
    tests_fill_report("tests_name", "OK");
    return SUCCESS;
}


static int tests_sd(void)
{
    char *filename = "tests_sd.txt";
    char *sdtext0 = "sdtext 1234567890 !@#$%^&*() -_+= `~ abcdefghijklmnopqrstuvwxyz \r \t ABCDEFGHIJKLMNOPQRSTUVWXYZ \n ,./<>?;:'\"\\|[]{}";
    char *sdtext1;
    
    sd_erase();
    
    if (sd_write(filename, sizeof(filename), sdtext0, strlen(sdtext0)) != SUCCESS) {
        tests_fill_report("tests_sd", "FAIL - File write");
        return ERROR;
    }
    
    sdtext1 = sd_load(filename, sizeof(filename));
    
    if (memcmp(sdtext0, sdtext1, strlen(sdtext0))) {
        tests_fill_report("tests_name", "FAIL - File read");
        return ERROR;
    }
  
    if (sd_list() == ERROR) {
        tests_fill_report("tests_name", "FAIL - List files");
        return ERROR;
    }
  
    // TODO check listed files for filename

    sd_erase();

    sdtext1 = sd_load(filename, sizeof(filename));
   
    if (sdtext1 != NULL) {
        tests_fill_report("tests_name", "FAIL - File not erased");
        return ERROR;
    }

    tests_fill_report("tests_sd", "OK");
    return SUCCESS;
}


static int tests_lock(void) 
{
    commander_force_reset();
    
    if (!memory_read_unlocked()) {
        tests_fill_report("tests_lock", "FAIL - Locked");
        return ERROR;
    }
    
    memory_write_unlocked(0); 
    
    if (memory_read_unlocked()) {
        tests_fill_report("tests_lock", "FAIL - Unlocked");
        return ERROR;
    }
  
    commander_force_reset();
    tests_fill_report("tests_lock", "OK");

    return SUCCESS;
}


void tests_internal(void)
{
    tests_reset();
    tests_random();
    tests_name();
    tests_sd();
    tests_lock();
    tests_backup();
    tests_sign_speed();	

    commander_clear_report();
    commander_fill_report("tests", tests_report, SUCCESS);

}
