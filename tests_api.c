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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "uECC.h"
#include "utils.h"
#include "jsmn.h"
#include "flags.h"
#include "random.h"
#include "commander.h"

// http://www.signal11.us/oss/hidapi/
#include "hidapi.h"


#define HID_MAX_STR       255
#define HID_REPORT_SIZE	  2048


extern const char *CMD_STR[];

static hid_device *HID_HANDLE;
static unsigned char HID_REPORT[HID_REPORT_SIZE] = {0};
static const char tests_pwd[] = "0000";
static int TEST_LIVE_DEVICE = 0;


static int tests_hid_init(void)
{
	HID_HANDLE = hid_open(0x03eb, 0x2402, NULL);
    if (!HID_HANDLE) {
        return ERROR;
    }
    return SUCCESS;
}


static void tests_hid_read(void)
{
   	int res;
    memset(HID_REPORT, 0, HID_REPORT_SIZE);
    res = hid_read(HID_HANDLE, HID_REPORT, HID_REPORT_SIZE);
	if (res < 0) {
		printf("ERROR: Unable to read report.\n");
    } else {
        utils_decrypt_report((char *)HID_REPORT);
        //printf("received:  >>%s<<\n", utils_read_decrypted_report());
    }
}


static void tests_hid_send_len(const char *cmd, int cmdlen)
{
   	int res;
	memset(HID_REPORT, 0, HID_REPORT_SIZE);
    memcpy(HID_REPORT, cmd, cmdlen );	
    res = hid_write(HID_HANDLE, (unsigned char*)HID_REPORT, HID_REPORT_SIZE);
}


static void tests_hid_send(const char *cmd)
{
    tests_hid_send_len(cmd, strlen(cmd));
}


static void tests_hid_send_encrypt(const char *cmd)
{
    int enc_len;
    char *enc = aes_cbc_b64_encrypt((unsigned char *)cmd, strlen(cmd), &enc_len, PASSWORD_STAND);
    tests_hid_send_len(enc, enc_len);
    free(enc);
}


static void tests_fill_report(const char *attr, const char *val)
{
    printf("%s:\t%s\n", attr, val);
    return;
}


static void tests_send_cmd(const char *command, PASSWORD_ID id)
{
    //printf("\nsending:   %i  >>%s<<\n", id, command);
    if (!TEST_LIVE_DEVICE) {
        utils_send_cmd(command, id);
    }
    else if (id == PASSWORD_NONE) {
        tests_hid_send(command);
        tests_hid_read();
    } 
    else {
        tests_hid_send_encrypt(command);
        tests_hid_read();
    }
}


static void tests_format_send_cmd(const char *cmd, const char* val, PASSWORD_ID id)
{
    char command[COMMANDER_REPORT_SIZE] = {0};
    strcpy(command, "{\"");
    strcat(command, cmd);
    strcat(command, "\": ");
    if (val[0] == '{') {
        strcat(command, val);
    } else {
        strcat(command, "\"");
        strcat(command, val);
        strcat(command, "\"");
    }
    strcat(command, "}");
    tests_send_cmd(command, id);
}


static void tests_reset(void)
{
    if (!TEST_LIVE_DEVICE) {
        commander_force_reset();
    } else {
        tests_format_send_cmd("reset", "__ERASE__", PASSWORD_NONE);
    }
}


static const char *tests_get_value(int cmd)
{
    int len;
    return jsmn_get_value_string(utils_read_decrypted_report(), CMD_STR[cmd], &len);
}


static int tests_report_has(const char *str)
{
    char *err;
    char *report = utils_read_decrypted_report();
    if (report) {
        //printf("report is:    %s\n", report);
        //printf("report has:   %s\n\n", str);
        err = strstr(report, str);
        if (err) {
            return 1;
        }
    }
    return 0;
}


static void tests_sign_speed(void)
{
	// N = 50 -> 7.5 sig/sec on chip
	uint8_t sig[64], priv_key_0[32], priv_key_1[32], msg[256];
	uint16_t time_ms;
	size_t i, N = 50; 
	int res;
	for (i = 0; i < sizeof(msg); i++) {
		msg[i] = i * 1103515245;
	}

	memcpy(priv_key_0, utils_hex_to_uint8("c55ece858b0ddd5263f96810fe14437cd3b5e1fbd7c6a2ec1e031f05e86d8bd5"), 32);
	memcpy(priv_key_1, utils_hex_to_uint8("509a0382ff5da48e402967a671bdcde70046d07f0df52cff12e8e3883b426a0a"), 32);

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
		sprintf(report, "%0.2f sig/s", N * 2.0 / ((float)time_ms / 1000));
		tests_fill_report("tests_sign_speed", report);
	}
}


static void tests_seed_xpub_backup(void)
{
    char xpub0[112], xpub1[112];
    char filename[] = "tests_backup.txt";
    char keypath[] = "m/44\'/0\'/";

    char seed_c[512], seed_b[512], back[512];
    const char **salt, **cipher, **run, **mnemo;
	static const char *options[] = {
	//  run     salt              encrypt       mnemonic
		"y",    "",               NULL,         NULL,
		"y",    "",               "no",         NULL,
		"y",    "",               "yes",        NULL,
		"y",    NULL,             NULL,         NULL,
		"y",    NULL,             "no",         NULL,
		"y",    NULL,             "yes",        NULL,
		"y",    "Digital Bitbox", NULL,         NULL,
		"y",    "Digital Bitbox", "no",         NULL,
		"y",    "Digital Bitbox", "yes",        NULL,
		"y",    NULL,             NULL,         "silent answer fury celery kitten amused pudding struggle infant cake jealous ready curve more fame gown leave then client biology unusual lazy potato bubble",
		"y",    NULL,             "no",         "silent answer fury celery kitten amused pudding struggle infant cake jealous ready curve more fame gown leave then client biology unusual lazy potato bubble",
		"y",    "",               "no",         "silent answer fury celery kitten amused pudding struggle infant cake jealous ready curve more fame gown leave then client biology unusual lazy potato bubble",
		"y",    "Digital Bitbox", "no",         "silent answer fury celery kitten amused pudding struggle infant cake jealous ready curve more fame gown leave then client biology unusual lazy potato bubble",
		"y",    NULL,             "yes",        "silent answer fury celery kitten amused pudding struggle infant cake jealous ready curve more fame gown leave then client biology unusual lazy potato bubble",
		"y",    "",               "yes",        "silent answer fury celery kitten amused pudding struggle infant cake jealous ready curve more fame gown leave then client biology unusual lazy potato bubble",
		"y",    "Digital Bitbox", "yes",        "silent answer fury celery kitten amused pudding struggle infant cake jealous ready curve more fame gown leave then client biology unusual lazy potato bubble",
        NULL,   NULL,             NULL,         NULL,
	};
    run = options;
    salt = options + 1;
	cipher = options + 2;
	mnemo = options + 3;



    tests_reset();
    tests_format_send_cmd("password", tests_pwd, PASSWORD_NONE); if (tests_report_has("error")) { goto err; }
    
    tests_format_send_cmd("seed", "{\"source\": \"ilent answer fury celery kitten amused pudding struggle infant cake jealous ready curve more fame gown leave then client biology unusual lazy potato bubble\"}", PASSWORD_STAND); 
    if (!tests_report_has(FLAG_ERR_MNEMO_CHECK)) { goto err; }

    tests_format_send_cmd("seed", "{\"source\": \"silent answer fury celery kitten amused pudding struggle infant cake jealous ready curve more fame gown leave then client biology unusual lazy potato bubble\"}", PASSWORD_STAND); 
    if (tests_report_has("error")) { goto err; }
        





    while (*run) {
  
        printf("backup test  %s\n", *salt); 
        printf("backup test  %s\n", *cipher); 
        printf("backup test  %s\n\n\n", *mnemo); 


        memset(seed_c, 0, sizeof(seed_c));
        memset(seed_b, 0, sizeof(seed_b));
        memset(back, 0, sizeof(back));
        
        strcpy(seed_c, "{\"source\":\"");
        if(*mnemo) { strcat(seed_c, *mnemo);
        } else {     strcat(seed_c, "create");
        }            strcat(seed_c, "\"");
        
        strcpy(seed_b, "{\"source\":\"");
        strcat(seed_b, filename);
        strcat(seed_b, "\"");
        
        strcpy(back, "{\"backup\":{\"filename\":\"");
        strcat(back, filename);
        strcat(back, "\"");
        
        
        if(*cipher) {
            strcat(seed_b, ",\"decrypt\":\"");
            strcat(seed_b, *cipher);
            strcat(seed_b, "\"");
            strcat(back, ",\"encrypt\":\"");
            strcat(back, *cipher);
            strcat(back, "\"");
        }
        if(*salt) {
            strcat(seed_c, ",\"salt\":\"");
            strcat(seed_c, *salt);
            strcat(seed_c, "\""); 
            strcat(seed_b, ",\"salt\":\"");
            strcat(seed_b, *salt);
            strcat(seed_b, "\"");
        }
        
        strcat(seed_c, "}");
        strcat(seed_b, "}");
        strcat(back, "}}");

        
        // erase
        tests_reset();
        tests_format_send_cmd("password", tests_pwd, PASSWORD_NONE); if (tests_report_has("error")) { goto err; }
        memset(xpub0, 0, sizeof(xpub0));
        memset(xpub1, 0, sizeof(xpub1));
        
        // create
        tests_format_send_cmd("xpub", keypath, PASSWORD_STAND);        if (!tests_report_has(FLAG_ERR_BIP32_MISSING)) { goto err; }
        tests_format_send_cmd("seed", seed_c, PASSWORD_STAND);         if ( tests_report_has("error")) { goto err; }
        tests_format_send_cmd("xpub", keypath, PASSWORD_STAND);        if ( tests_report_has("error")) { goto err; }
        memcpy(xpub0, tests_get_value(CMD_xpub_), sizeof(xpub0));
        if (!memcmp(xpub0, xpub1, 112)) { goto err; }
        // backup
        tests_format_send_cmd("verifypass", "export", PASSWORD_STAND); if ( tests_report_has("error")) { goto err; } 
        tests_format_send_cmd("backup", "erase", PASSWORD_STAND);      if ( tests_report_has("error")) { goto err; }
        tests_format_send_cmd("backup", back, PASSWORD_STAND);         if ( tests_report_has("error")) { goto err; }
        // erase
        tests_reset();
        tests_format_send_cmd("password", tests_pwd, PASSWORD_NONE);   if ( tests_report_has("error")) { goto err; }
        
        // load backup default
        tests_format_send_cmd("seed", seed_b, PASSWORD_STAND);         if ( tests_report_has("error")) { goto err; }
        tests_format_send_cmd("xpub", keypath, PASSWORD_STAND);        if ( tests_report_has("error")) { goto err; }
        memcpy(xpub1, tests_get_value(CMD_xpub_), sizeof(xpub1));
        // check xpubs
        if (memcmp(xpub0, xpub1, 112)) { goto err; }
        // check backup list and erase
        tests_format_send_cmd("backup", "list", PASSWORD_STAND);       if (!tests_report_has(filename)) { goto err; }
        tests_format_send_cmd("backup", "erase", PASSWORD_STAND);      if ( tests_report_has(filename)) { goto err; }

        
        run += 4;
        salt += 4;
        cipher += 4;
        mnemo += 4;
    } 
   
    tests_format_send_cmd("led", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }  
    tests_format_send_cmd("xpub", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; } 
    tests_format_send_cmd("seed", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; } 
    tests_format_send_cmd("sign", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; } 
    tests_format_send_cmd("reset", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }
    tests_format_send_cmd("backup", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }
    tests_format_send_cmd("random", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }
    tests_format_send_cmd("device", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }
    tests_format_send_cmd("verifypass", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; } 


    tests_fill_report("tests_seed_xpub_backup", "OK");
    return;

    err:
        tests_fill_report("tests_seed_xpub_backup", "FAIL");
        tests_fill_report("tests_seed_xpub_backup", utils_read_decrypted_report());
}


static void tests_random(void)
{
    char number0[32] = {0};
    char number1[32] = {0};

    tests_reset();
    tests_format_send_cmd("password", tests_pwd, PASSWORD_NONE); if (tests_report_has("error")) { goto err; }
    
    tests_format_send_cmd("random", "pseudo", PASSWORD_STAND); if (tests_report_has("error")) { goto err; }
    memcpy(number0, tests_get_value(CMD_random_), sizeof(number0)); 
    
    tests_format_send_cmd("random","pseudo", PASSWORD_STAND); if (tests_report_has("error")) { goto err; }
    memcpy(number1, tests_get_value(CMD_random_), sizeof(number1)); 
    if (!memcmp(number0, number1, 32)) { goto err; }

    tests_format_send_cmd("random", "true", PASSWORD_STAND); if (tests_report_has("error")) { goto err; }
    memcpy(number0, tests_get_value(CMD_random_), sizeof(number0)); 
    
    tests_format_send_cmd("random", "true", PASSWORD_STAND); if (tests_report_has("error")) { goto err; }
    memcpy(number1, tests_get_value(CMD_random_), sizeof(number1)); 
    if (!memcmp(number0, number1, 32)) { goto err; }
    
    
    tests_fill_report("tests_random", "OK");
    return;
    
    err:
        tests_fill_report("tests_random", "FAIL");
        tests_fill_report("tests_random", utils_read_decrypted_report());
}


static void tests_name(void)
{
    char name0[] = "name0";
    char name1[] = "name1";
    char name[5];
  
    tests_reset();
    tests_format_send_cmd("password", tests_pwd, PASSWORD_NONE); 
    if (tests_report_has("error")) { goto err; }
    
    tests_format_send_cmd("name", name0, PASSWORD_STAND);  
    if (tests_report_has("error")) { goto err; }
    memcpy(name, tests_get_value(CMD_name_), sizeof(name));
    if (memcmp(name0, name, sizeof(name))) { goto err; }
    
    tests_format_send_cmd("name", name1, PASSWORD_STAND);   
    if (tests_report_has("error")) { goto err; }
    memcpy(name, tests_get_value(CMD_name_), sizeof(name));
    if (memcmp(name1, name, sizeof(name))) { goto err; }
    
    tests_format_send_cmd("name", "", PASSWORD_STAND); 
    if (tests_report_has("error")) { goto err; }
    memcpy(name, tests_get_value(CMD_name_), sizeof(name));
    if (memcmp(name1, name, sizeof(name))) { goto err; }


    tests_fill_report("tests_name", "OK");
    return;
    
    err:
        tests_fill_report("tests_name", "FAIL");
        tests_fill_report("tests_name", utils_read_decrypted_report());
}


static void tests_device(void) 
{
    char s[] = "{\"source\":\"create\"}";

    tests_reset();
    tests_format_send_cmd("password", tests_pwd, PASSWORD_NONE);   if (tests_report_has("error")) { goto err; }
    tests_format_send_cmd("seed", s, PASSWORD_STAND);              if (tests_report_has("error")) { goto err; }
    tests_format_send_cmd("verifypass", "create", PASSWORD_STAND); if (tests_report_has("error")) { goto err; }
    tests_send_cmd("{\"backup\":{\"filename\":\"b.txt\"}}", PASSWORD_STAND); if (tests_report_has("error")) { goto err; }
    
    tests_format_send_cmd("device", "lock", PASSWORD_STAND);       if (tests_report_has("error")) { goto err; } 
    tests_format_send_cmd("seed", s, PASSWORD_STAND);              if (!tests_report_has(FLAG_ERR_DEVICE_LOCKED)) { goto err; }
    tests_format_send_cmd("verifypass", "create", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_DEVICE_LOCKED)) { goto err; }
    tests_send_cmd("{\"backup\":{\"filename\":\"b.txt\"}}", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_DEVICE_LOCKED)) { goto err; }
  
    tests_format_send_cmd("device", "serial", PASSWORD_STAND);     if (tests_report_has("error")) { goto err; } 
    tests_format_send_cmd("device", "version", PASSWORD_STAND);    if (tests_report_has("error")) { goto err; } 
                                                              if (!tests_report_has(DIGITAL_BITBOX_VERSION)) { goto err; }

    tests_fill_report("tests_device", "OK");
    return;
    
    err:
        tests_fill_report("tests_device", "FAIL");
        tests_fill_report("tests_device", utils_read_decrypted_report());
}


static void tests_input(void)
{
    int i;

    tests_reset();
    if (!TEST_LIVE_DEVICE) {
        tests_send_cmd("", PASSWORD_NONE); if (!tests_report_has(FLAG_ERR_NO_INPUT))                       { goto err; }
        tests_send_cmd(NULL, PASSWORD_NONE); if (!tests_report_has(FLAG_ERR_NO_INPUT))                     { goto err; }
    }
    tests_format_send_cmd("password", tests_pwd, PASSWORD_NONE); if (tests_report_has("error"))                 { goto err; }
    
    tests_send_cmd("{\"name\": \"name\"}",      PASSWORD_NONE);    if (!tests_report_has(FLAG_ERR_DECRYPT))     { goto err; }
    tests_send_cmd("{\"name\": \"name\"}",      PASSWORD_STAND);   if ( tests_report_has("error"))              { goto err; }
    tests_send_cmd("\"name\": \"name\"}",       PASSWORD_STAND);   if (!tests_report_has(FLAG_ERR_JSON_PARSE))  { goto err; }
    tests_send_cmd("{name\": \"name\"}",        PASSWORD_STAND);   if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }
    tests_format_send_cmd("name", "avoidreset", PASSWORD_STAND);   if ( tests_report_has("error"))              { goto err; }
    tests_send_cmd("{\"name: \"name\"}",        PASSWORD_STAND);   if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }
    tests_send_cmd("{\"name\": \"name}",        PASSWORD_STAND);   if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }
    tests_format_send_cmd("name", "avoidreset", PASSWORD_STAND);   if ( tests_report_has("error"))              { goto err; }
    tests_send_cmd("{\"name\": \"name\"",       PASSWORD_STAND);   if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }
    tests_send_cmd("{\"name\": \"name\", }",    PASSWORD_STAND);   if ( tests_report_has("error"))              { goto err; }
    tests_send_cmd("{\"name\": \"name\", \"name\"}", PASSWORD_STAND);           if (!tests_report_has(FLAG_ERR_MULTIPLE_CMD)) { goto err; }
    tests_send_cmd("{\"name\": \"name\", \"name\": }", PASSWORD_STAND);         if (!tests_report_has(FLAG_ERR_MULTIPLE_CMD)) { goto err; }
    tests_send_cmd("{\"name\": \"name\", \"name\": \"name\"}", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_MULTIPLE_CMD)) { goto err; }
    tests_format_send_cmd("name", "avoidreset", PASSWORD_STAND);   if ( tests_report_has("error"))              { goto err; }
    
    for (i = 0; i < COMMANDER_MAX_ATTEMPTS - 1; i++) {
        tests_send_cmd("{\"name\": \"name\"}", PASSWORD_NONE); 
        if (!tests_report_has(FLAG_ERR_DECRYPT))   { goto err; }
        if (!tests_report_has(FLAG_ERR_RESET_WARNING))   { goto err; }
    }
    tests_send_cmd("{\"name\": \"name\"}", PASSWORD_NONE); if (!tests_report_has(FLAG_ERR_RESET))   { goto err; }
    
    tests_fill_report("tests_input", "OK");
    return;
    
    err:
        tests_fill_report("tests_input", "FAIL");
        tests_fill_report("tests_input", utils_read_decrypted_report());
}


static void tests_password(void)
{
    tests_reset();
    tests_format_send_cmd("name", "", PASSWORD_NONE);            if (!tests_report_has(FLAG_ERR_NO_PASSWORD))  { goto err; }
    tests_format_send_cmd("password", "123", PASSWORD_NONE);     if (!tests_report_has(FLAG_ERR_PASSWORD_LEN)) { goto err; }
    tests_format_send_cmd("password", tests_pwd, PASSWORD_NONE); if ( tests_report_has("error"))                { goto err; }
    tests_format_send_cmd("password", tests_pwd, PASSWORD_NONE); if (!tests_report_has(FLAG_ERR_DECRYPT))      { goto err; }
    tests_format_send_cmd("password", "123", PASSWORD_STAND);    if (!tests_report_has(FLAG_ERR_PASSWORD_LEN)) { goto err; }
    
    tests_fill_report("tests_password", "OK");
    return;
    
    err:
        tests_fill_report("tests_password", "FAIL");
        tests_fill_report("tests_password", utils_read_decrypted_report());
}


static void tests_verifypass(void)
{
    char create[] = "create";
    char export[] = "export";
    char seed[] = "{\"source\":\"create\"}";
    char hash_sign[] = "{\"type\":\"hash\", \"keypath\":\"m/\", \"data\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}";
    char hash_sign2[] = "{\"type\":\"hash\", \"keypath\":\"m/\", \"data\":\"ffff456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}";
    char hash_sign3[] = "{\"type\":\"hash\", \"keypath\":\"m/\", \"data\":\"456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}";

    tests_reset();
    tests_format_send_cmd("password", tests_pwd, PASSWORD_NONE);  if ( tests_report_has("error")) { goto err; }
    tests_format_send_cmd("sign", hash_sign2, PASSWORD_STAND);    if (!tests_report_has("echo"))  { goto err; }
    tests_format_send_cmd("sign", hash_sign2, PASSWORD_STAND);    if (!tests_report_has(FLAG_ERR_BIP32_MISSING)) { goto err; }
    tests_format_send_cmd("seed", seed, PASSWORD_STAND);          if ( tests_report_has("error")) { goto err; }

    // test verifypass
    tests_format_send_cmd("verifypass", create, PASSWORD_STAND);  if ( tests_report_has("error"))              { goto err; }
    tests_format_send_cmd("backup", "erase", PASSWORD_STAND);     if ( tests_report_has("error"))              { goto err; }
    tests_format_send_cmd("backup", "list", PASSWORD_STAND);      if ( tests_report_has(VERIFYPASS_FILENAME))  { goto err; } 
    tests_format_send_cmd("verifypass", export, PASSWORD_STAND);  if ( tests_report_has("error"))              { goto err; } 
    tests_format_send_cmd("backup", "list", PASSWORD_STAND);      if (!tests_report_has(VERIFYPASS_FILENAME))  { goto err; } 
    
    // test echo
    tests_format_send_cmd("sign", hash_sign, PASSWORD_STAND);     if (!tests_report_has("echo")) { goto err; }
    tests_format_send_cmd("sign", hash_sign, PASSWORD_STAND);     if ( tests_report_has("echo")) { goto err; } 
    tests_format_send_cmd("sign", hash_sign2, PASSWORD_STAND);    if (!tests_report_has("echo")) { goto err; } 
    tests_format_send_cmd("sign", hash_sign, PASSWORD_STAND);     if (!tests_report_has("echo")) { goto err; } 
    tests_format_send_cmd("sign", hash_sign, PASSWORD_STAND);     if ( tests_report_has("2FA"))  { goto err; } 
    tests_format_send_cmd("sign", hash_sign2, PASSWORD_STAND);    if (!tests_report_has("echo")) { goto err; } 
   
    // test hash length
    tests_format_send_cmd("sign", hash_sign3, PASSWORD_STAND);    if (!tests_report_has("echo")) { goto err; } 
    tests_format_send_cmd("sign", hash_sign3, PASSWORD_STAND);    if (!tests_report_has(FLAG_ERR_SIGN_LEN)) { goto err; } 

    // test locked
    tests_format_send_cmd("device", "lock", PASSWORD_STAND);      if ( tests_report_has("error")) { goto err; }
    tests_format_send_cmd("sign", hash_sign, PASSWORD_STAND);     if (!tests_report_has("echo"))  { goto err; } 
    tests_format_send_cmd("sign", hash_sign, PASSWORD_STAND);     if (!tests_report_has("2FA"))   { goto err; } 
    tests_format_send_cmd("seed", seed, PASSWORD_STAND);          if (!tests_report_has(FLAG_ERR_DEVICE_LOCKED)) { goto err; } 
    tests_format_send_cmd("verifypass", export, PASSWORD_STAND);  if (!tests_report_has(FLAG_ERR_DEVICE_LOCKED)) { goto err; } 
    tests_format_send_cmd("backup", "list", PASSWORD_STAND);      if (!tests_report_has(FLAG_ERR_DEVICE_LOCKED)) { goto err; } 

    tests_fill_report("tests_verifypass", "OK");
    return;
    
    err:
        tests_fill_report("tests_verifypass", "FAIL");
        tests_fill_report("tests_verifypass", utils_read_decrypted_report());
}

    
static void tests_sign(void)
{
    tests_reset();
    tests_format_send_cmd("password", tests_pwd, PASSWORD_NONE); if (tests_report_has("error")) { goto err; }
    
    // signing before seeded
    tests_format_send_cmd("sign", "{\"type\":\"transaction\", \"data\":\"0100000001e4b8a097d6d5cd351f69d9099e277b8a1c39a219991a4e5f9f86805faf649899010000001976a91488e6399fab42b2ea637da283dd87e70f4862e10c88acffffffff0298080000000000001976a91452922e52d08a2c1f1e4120803e56363fd7a8195188acb83d0000000000001976a914fd342347278e14013d17d53ed3c4aa7bf27eceb788ac0000000001000000\", \"keypath\":\"m/44'/0'/0'/1/7\", \"change_keypath\":\"m/44'/0'/0'/1/8\"} }", PASSWORD_STAND);
    if (!tests_report_has(FLAG_ERR_DESERIALIZE))          { goto err; }  

    // seed
    tests_format_send_cmd("seed", "{\"source\":\"bronze science bulk conduct fragile genius bone miracle twelve grab maid peace observe illegal exchange space another usage hunt donate feed swarm arrest naive\"}}", PASSWORD_STAND);
    if (tests_report_has("error")) { goto err; }

    // wrong change keypath
    tests_format_send_cmd("sign", "{\"type\":\"transaction\", \"data\":\"0100000001e4b8a097d6d5cd351f69d9099e277b8a1c39a219991a4e5f9f86805faf649899010000001976a91488e6399fab42b2ea637da283dd87e70f4862e10c88acffffffff0298080000000000001976a91452922e52d08a2c1f1e4120803e56363fd7a8195188acb83d0000000000001976a914fd342347278e14013d17d53ed3c4aa7bf27eceb788ac0000000001000000\", \"keypath\":\"m/44'/0'/0'/1/7\", \"change_keypath\":\"m/\"} }", PASSWORD_STAND);
    if (!tests_report_has(FLAG_ERR_DESERIALIZE))          { goto err; }  
 
    // change output after echo (MITM attack)
    tests_format_send_cmd("sign", "{\"type\":\"transaction\", \"data\":\"0100000001e4b8a097d6d5cd351f69d9099e277b8a1c39a219991a4e5f9f86805faf649899010000001976a91488e6399fab42b2ea637da283dd87e70f4862e10c88acffffffff0298080000000000001976a91452922e52d08a2c1f1e4120803e56363fd7a8195188acb83d0000000000001976a914fd342347278e14013d17d53ed3c4aa7bf27eceb788ac0000000001000000\", \"keypath\":\"m/44'/0'/0'/1/7\", \"change_keypath\":\"m/44'/0'/0'/1/8\"} }", PASSWORD_STAND);
    if (!tests_report_has("echo"))          { goto err; }  
    if (tests_report_has("error"))          { goto err; }  
    tests_format_send_cmd("sign", "{\"type\":\"transaction\", \"data\":\"0100000001e4b8a097d6d5cd351f69d9099e277b8a1c39a219991a4e5f9f86805faf649899010000001976a91488e6399fab42b2ea637da283dd87e7af4862e10c88acffffffff0298080000000000001976a91488e6399fab42b2ea637da283dd87e70f4862e10c88acb83d0000000000001976a914fd342347278e14013d17d53ed3c4aa7bf27eceb788ac0000000001000000\", \"keypath\":\"m/44'/0'/0'/1/7\", \"change_keypath\":\"m/44'/0'/0'/1/8\"} }", PASSWORD_STAND);
    if (!tests_report_has("echo"))          { goto err; }  
    if ( tests_report_has("sign"))          { goto err; }  

    // sign using one input
    tests_format_send_cmd("sign", "{\"type\":\"transaction\", \"data\":\"0100000001e4b8a097d6d5cd351f69d9099e277b8a1c39a219991a4e5f9f86805faf649899010000001976a91488e6399fab42b2ea637da283dd87e70f4862e10c88acffffffff0298080000000000001976a91452922e52d08a2c1f1e4120803e56363fd7a8195188acb83d0000000000001976a914fd342347278e14013d17d53ed3c4aa7bf27eceb788ac0000000001000000\", \"keypath\":\"m/44'/0'/0'/1/7\", \"change_keypath\":\"m/44'/0'/0'/1/8\"} }", PASSWORD_STAND);
    if (!tests_report_has("echo"))          { goto err; }  
    if (!tests_report_has("verify_output")) { goto err; }
    if (!tests_report_has("value"))         { goto err; }
    if (!tests_report_has("2200"))          { goto err; }
    if (!tests_report_has("script"))        { goto err; }
    if (!tests_report_has("76a91452922e52d08a2c1f1e4120803e56363fd7a8195188ac")) { goto err; }
    tests_format_send_cmd("sign", "{\"type\":\"transaction\", \"data\":\"0100000001e4b8a097d6d5cd351f69d9099e277b8a1c39a219991a4e5f9f86805faf649899010000001976a91488e6399fab42b2ea637da283dd87e70f4862e10c88acffffffff0298080000000000001976a91452922e52d08a2c1f1e4120803e56363fd7a8195188acb83d0000000000001976a914fd342347278e14013d17d53ed3c4aa7bf27eceb788ac0000000001000000\", \"keypath\":\"m/44'/0'/0'/1/7\", \"change_keypath\":\"m/44'/0'/0'/1/8\"} }", PASSWORD_STAND);
    if (!tests_report_has("sign"))          { goto err; }  
    if (!tests_report_has("41fa23804d6fe53c296a5ac93a2e21719f9c6f20b2645d04d047150087cd812acedefc98a7d87f1379efb84dc684ab947dc4e583d2c3e1d50f372012b3d8c95e")) { goto err; }  
    if (!tests_report_has("pubkey"))        { goto err; }  
    if (!tests_report_has("02721be181276eebdc4dd29dce180afa7c6a8199fb5f4c09f2e03b8e4193f22ce5")) { goto err; }  

    // sign using two inputs 
    tests_format_send_cmd("sign", "{\"type\":\"transaction\", \"data\":\"01000000029ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f000000001976a91452922e52d08a2c1f1e4120803e56363fd7a8195188acffffffff9ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f0100000000ffffffff01c8000000000000001976a914584495bb22f4cb66cd47f2255cbc7178c6f3caeb88ac0000000001000000\", \"keypath\":\"m/44'/0'/0'/0/5\", \"change_keypath\":\"None\"} }", PASSWORD_STAND);
    if (!tests_report_has("echo"))          { goto err; }  
    if (!tests_report_has("verify_output")) { goto err; }
    if (!tests_report_has("value"))         { goto err; }
    if (!tests_report_has("200"))          { goto err; }
    if (!tests_report_has("script"))        { goto err; }
    if (!tests_report_has("76a914584495bb22f4cb66cd47f2255cbc7178c6f3caeb88ac")) { goto err; }
    tests_format_send_cmd("sign", "{\"type\":\"transaction\", \"data\":\"01000000029ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f000000001976a91452922e52d08a2c1f1e4120803e56363fd7a8195188acffffffff9ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f0100000000ffffffff01c8000000000000001976a914584495bb22f4cb66cd47f2255cbc7178c6f3caeb88ac0000000001000000\", \"keypath\":\"m/44'/0'/0'/0/5\", \"change_keypath\":\"None\"} }", PASSWORD_STAND);
    if (!tests_report_has("sign"))          { goto err; }  
    if (!tests_report_has("031145194147dada762c77ff85fd5cb493f56596de20f235c35507cd72716134e49cbe288c46f90da19bd1552c406e64425169520d433113a78b480ca3c5d340")) { goto err; }  
    if (!tests_report_has("pubkey"))        { goto err; }  
    if (!tests_report_has("0367d99d26d908bc11adaf05e1c18072b67e825f27dfadd504b013bafaa0f364a6")) { goto err; }  
    tests_format_send_cmd("sign", "{\"type\":\"transaction\", \"data\":\"01000000029ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f0000000000ffffffff9ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f010000001976a914fd342347278e14013d17d53ed3c4aa7bf27eceb788acffffffff01c8000000000000001976a914584495bb22f4cb66cd47f2255cbc7178c6f3caeb88ac0000000001000000\", \"keypath\":\"m/44'/0'/0'/1/8\", \"change_keypath\":\"None\"} }", PASSWORD_STAND);
    if (!tests_report_has("sign"))          { goto err; }  
    if (!tests_report_has("d4464e76d679b062ec867c7ebb961fc27cab810ccd6198bd993acef5a84273bcf16b256cfd77768df1bbce20333904c5e93873cee26ac446afdd62a5394b73ad")) { goto err; }  
    if (!tests_report_has("pubkey"))        { goto err; }  
    if (!tests_report_has("032ab901fe42a05e970e6d5c701b4d7a6db33b0fa7daaaa709ebe755daf9dfe0ec")) { goto err; }  


    // lock to get 2FA PINs
    tests_format_send_cmd("device", "lock", PASSWORD_STAND); if ( tests_report_has("error")) { goto err; }


    // sign using one input
    tests_format_send_cmd("sign", "{\"type\":\"transaction\", \"data\":\"0100000001e4b8a097d6d5cd351f69d9099e277b8a1c39a219991a4e5f9f86805faf649899010000001976a91488e6399fab42b2ea637da283dd87e70f4862e10c88acffffffff0298080000000000001976a91452922e52d08a2c1f1e4120803e56363fd7a8195188acb83d0000000000001976a914fd342347278e14013d17d53ed3c4aa7bf27eceb788ac0000000001000000\", \"keypath\":\"m/44'/0'/0'/1/7\", \"change_keypath\":\"m/44'/0'/0'/1/8\"} }", PASSWORD_STAND);
    memory_write_aeskey(tests_get_value(CMD_pin_), 4, PASSWORD_2FA);
    if (!tests_report_has("echo"))          { goto err; }  
    if (!tests_report_has("verify_output")) { goto err; }
    if (!tests_report_has("value"))         { goto err; }
    if (!tests_report_has("2200"))          { goto err; }
    if (!tests_report_has("script"))        { goto err; }
    if (!tests_report_has("76a91452922e52d08a2c1f1e4120803e56363fd7a8195188ac")) { goto err; }
    tests_format_send_cmd("sign", "{\"type\":\"transaction\", \"data\":\"0100000001e4b8a097d6d5cd351f69d9099e277b8a1c39a219991a4e5f9f86805faf649899010000001976a91488e6399fab42b2ea637da283dd87e70f4862e10c88acffffffff0298080000000000001976a91452922e52d08a2c1f1e4120803e56363fd7a8195188acb83d0000000000001976a914fd342347278e14013d17d53ed3c4aa7bf27eceb788ac0000000001000000\", \"keypath\":\"m/44'/0'/0'/1/7\", \"change_keypath\":\"m/44'/0'/0'/1/8\"} }", PASSWORD_STAND);
    if (!tests_report_has("2FA"))           { goto err; }
    if (!tests_report_has("sign"))          { goto err; }  
    if (!tests_report_has("41fa23804d6fe53c296a5ac93a2e21719f9c6f20b2645d04d047150087cd812acedefc98a7d87f1379efb84dc684ab947dc4e583d2c3e1d50f372012b3d8c95e")) { goto err; }  
    if (!tests_report_has("pubkey"))        { goto err; }  
    if (!tests_report_has("02721be181276eebdc4dd29dce180afa7c6a8199fb5f4c09f2e03b8e4193f22ce5")) { goto err; }  
   

    // sign using two inputs 
    tests_format_send_cmd("sign", "{\"type\":\"transaction\", \"data\":\"01000000029ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f000000001976a91452922e52d08a2c1f1e4120803e56363fd7a8195188acffffffff9ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f0100000000ffffffff01c8000000000000001976a914584495bb22f4cb66cd47f2255cbc7178c6f3caeb88ac0000000001000000\", \"keypath\":\"m/44'/0'/0'/0/5\", \"change_keypath\":\"None\"} }", PASSWORD_STAND);
    memory_write_aeskey(tests_get_value(CMD_pin_), 4, PASSWORD_2FA);
    if (!tests_report_has("echo"))          { goto err; }  
    if (!tests_report_has("verify_output")) { goto err; }
    if (!tests_report_has("value"))         { goto err; }
    if (!tests_report_has("200"))          { goto err; }
    if (!tests_report_has("script"))        { goto err; }
    if (!tests_report_has("76a914584495bb22f4cb66cd47f2255cbc7178c6f3caeb88ac")) { goto err; }
    tests_format_send_cmd("sign", "{\"type\":\"transaction\", \"data\":\"01000000029ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f000000001976a91452922e52d08a2c1f1e4120803e56363fd7a8195188acffffffff9ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f0100000000ffffffff01c8000000000000001976a914584495bb22f4cb66cd47f2255cbc7178c6f3caeb88ac0000000001000000\", \"keypath\":\"m/44'/0'/0'/0/5\", \"change_keypath\":\"None\"} }", PASSWORD_STAND);
    if (!tests_report_has("2FA"))           { goto err; }
    if (!tests_report_has("sign"))          { goto err; }  
    if (!tests_report_has("031145194147dada762c77ff85fd5cb493f56596de20f235c35507cd72716134e49cbe288c46f90da19bd1552c406e64425169520d433113a78b480ca3c5d340")) { goto err; }  
    if (!tests_report_has("pubkey"))        { goto err; }  
    if (!tests_report_has("0367d99d26d908bc11adaf05e1c18072b67e825f27dfadd504b013bafaa0f364a6")) { goto err; }  
    tests_format_send_cmd("sign", "{\"type\":\"transaction\", \"data\":\"01000000029ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f0000000000ffffffff9ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f010000001976a914fd342347278e14013d17d53ed3c4aa7bf27eceb788acffffffff01c8000000000000001976a914584495bb22f4cb66cd47f2255cbc7178c6f3caeb88ac0000000001000000\", \"keypath\":\"m/44'/0'/0'/1/8\", \"change_keypath\":\"None\"} }", PASSWORD_STAND);
    if (!tests_report_has("2FA"))           { goto err; }
    if (!tests_report_has("sign"))          { goto err; }  
    if (!tests_report_has("d4464e76d679b062ec867c7ebb961fc27cab810ccd6198bd993acef5a84273bcf16b256cfd77768df1bbce20333904c5e93873cee26ac446afdd62a5394b73ad")) { goto err; }  
    if (!tests_report_has("pubkey"))        { goto err; }  
    if (!tests_report_has("032ab901fe42a05e970e6d5c701b4d7a6db33b0fa7daaaa709ebe755daf9dfe0ec")) { goto err; }  


    tests_fill_report("tests_sign", "OK");
    return;
    
    err:
        tests_fill_report("tests_sign", "FAIL");
        tests_fill_report("tests_sign", utils_read_decrypted_report());
}
    
    

// test vectors generated from Python 2.7 code using aes, base64, and hashlib imports 
static void tests_aes_cbc(void)
{
	const char **plainp, **cipherp;

    char password[] = "{\"type\":\"password\", \"data\":\"passwordpassword\"}";
    char encrypt[] = "{\"type\":\"encrypt\", \"data\":\"";
    char decrypt[] = "{\"type\":\"decrypt\", \"data\":\"";
    char enc[COMMANDER_REPORT_SIZE * 2], dec[COMMANDER_REPORT_SIZE * 2];

	static const char *aes_vector[] = {
		// plain                               cipher
        "digital bitbox", "mheIJghfKiPxQpvqbbRCZnTkbMd+BdRf+1jDAjk9h2Y=",
        "Satoshi Nakamoto", "28XHUwA+/5zHeSIxt1Ioaifl/BqWsTow1hrzJJ7p91EgYbw6MwzFMlLOWq22fUsw",
        "All those moments will be lost in time, like tears in rain. Time to die...", "qjfyIWCoY8caehZFoZStmtDz6FaKYCaCrJXyiF6I2LwnLPVV9oGv9NtJ7aVXAICeP0Q2Agh0oPlbBLKfjkdtZGuwV/tya7KcIl1ieC/276JwRl2+XdkK3uBb2Yrljl4T",
        "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!", "biR4Ce1vnvrYAOQRwO+bW4aXiySH4plHVc9LlN8hJAb/q6Tw0x6aI+A7EeOF5a11EPTjJ454nREZ9S4nIBwlGDto2GrEq+TwQOpKb/YU1VxeGGlFLg8comVnVSPmNQ1WNX/E5bnNX8osgF69QFxOgaPzfLdKGr4isUBVO3BlOPV4oUmIUc7+DC5PwabWV4XrxLQzzw79KRxL3iPk4Tbk3CDxDBgE5Z7HlvZfTM5J9d7majdQTMtHYP7d1MJZblyTkB1R7DemQhf7xHllkSXwHattstz/d1NmgGQXHlISoPs=",	
        0, 0,
	};
	
    tests_reset();
    tests_format_send_cmd("password", tests_pwd, PASSWORD_NONE);  if (tests_report_has("error")) { goto err; }
    
    memcpy(dec, decrypt, strlen(decrypt));
    strcat(dec, "password not set error\"}");   
    tests_format_send_cmd("aes256cbc", dec, PASSWORD_STAND);      if (!tests_report_has(FLAG_ERR_NO_PASSWORD)) { goto err; }
    tests_format_send_cmd("aes256cbc", password, PASSWORD_STAND); if ( tests_report_has("error")) { goto err; }
    tests_format_send_cmd("aes256cbc", "type", PASSWORD_STAND);   if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }
    tests_format_send_cmd("aes256cbc", "", PASSWORD_STAND);       if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }
    
    memcpy(dec, decrypt, strlen(decrypt));
    memset(dec + strlen(decrypt), 'a', DATA_LEN_MAX + 1);   
    strcat(dec, "\"}");
    tests_format_send_cmd("aes256cbc", dec, PASSWORD_STAND);      
    if (!tests_report_has(FLAG_ERR_DATA_LEN)) { goto err; }
    
    tests_format_send_cmd("aes256cbc", "{\"type\":\"\", \"data\":\"\"}", PASSWORD_STAND);         
    if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }
    
    tests_format_send_cmd("aes256cbc", "{\"type\":\"encrypt\", \"data\":\"\"}", PASSWORD_STAND);  
    if (tests_report_has("error")) { goto err; }
    
    tests_format_send_cmd("aes256cbc", "{\"type\":\"decrypt\", \"data\":\"\"}", PASSWORD_STAND); 
    if (!tests_report_has(FLAG_ERR_NO_INPUT)) { goto err; }


    plainp = aes_vector;
	cipherp = aes_vector + 1;
	while (*plainp && *cipherp) {

        // check decryption 
        memset(dec, 0, sizeof(dec));
        memcpy(dec, decrypt, strlen(decrypt));
        memcpy(dec + strlen(decrypt), *cipherp, strlen(*cipherp));
        strcat(dec, "\"}");   
        
        tests_format_send_cmd("aes256cbc", dec, PASSWORD_STAND); 
        if (tests_report_has("error")) { goto err; }
        if (memcmp(*plainp, tests_get_value(CMD_aes256cbc_), strlen(*plainp))) { goto err; }

        // check encryption by encrypting then decrypting
        memset(enc, 0, sizeof(enc));
        memcpy(enc, encrypt, strlen(encrypt));
        memcpy(enc + strlen(encrypt), *plainp, strlen(*plainp));
        strcat(enc, "\"}");   
        
        tests_format_send_cmd("aes256cbc", enc, PASSWORD_STAND); 
        if (tests_report_has("error")) { goto err; }
        
        const char *e = tests_get_value(CMD_aes256cbc_);

        memset(dec, 0, sizeof(dec));
        memcpy(dec, decrypt, strlen(decrypt));
        memcpy(dec + strlen(decrypt), e, strlen(e));
        
        tests_format_send_cmd("aes256cbc", dec, PASSWORD_STAND); 
        if (tests_report_has("error")) { goto err; }
        if (memcmp(*plainp, tests_get_value(CMD_aes256cbc_), strlen(*plainp))) { goto err; }


        plainp += 2; cipherp += 2;
	}
    
    tests_fill_report("tests_aes_cbc", "OK");
    return;
    
    err:
        tests_fill_report("tests_aes_cbc", "FAIL");
        tests_fill_report("tests_aes_cbc", utils_read_decrypted_report());
}


static void tests_run(void)
{

    tests_seed_xpub_backup();
    return;
    
    tests_sign();
    return;
    
    tests_name();
    tests_password();
    tests_device();
    tests_random();
    tests_input();
    tests_aes_cbc();
    tests_verifypass();
    tests_sign_speed();	
}


int main(void)
{
   
    // Test the C code API  
    TEST_LIVE_DEVICE = 0;
    random_init();
    memory_setup();
    printf("\nInternal API Result:\n");
    tests_run();
   
    // Live test of the HID API
    // Requires the hidapi library to be installed:
    //     http://www.signal11.us/oss/hidapi/
    TEST_LIVE_DEVICE = 1;
    memory_write_aeskey(tests_pwd, 4, PASSWORD_STAND);
    
    if (tests_hid_init() == ERROR) {
        printf("Not testing HID API. A device is not connected.\n\n");
        return 1;
    }
    
    printf("\nHID API Result:\n");
    tests_run();

    return 0;
}
