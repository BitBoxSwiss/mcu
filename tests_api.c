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
static char tests_report[COMMANDER_REPORT_SIZE] = {0};
static const char tests_pwd[] = "0000";
static int TEST_INTERNAL = 0;


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
    strcat(tests_report, "\" }"); 
}


static void tests_send_cmd(const char *command, PASSWORD_ID id)
{
    if (TEST_INTERNAL) {
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
    if (TEST_INTERNAL) {
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


static void tests_backup_seed_xpub(void)
{
    char xpub0[112], xpub1[112];
    char filename[] = "tests_backup.txt";
    char keypath[] = "m/44\'/0\'/";

    char seed_c[512], seed_b[512], back[512];
    const char **salt, **cipher, **run, **mnemo;
	static const char *options[] = {
	//  run     salt              encrypt       mnemonic
		"y",    NULL,             NULL,         NULL,
		"y",    NULL,             "no",         NULL,
		"y",    NULL,             "yes",        NULL,
		"y",    "Digital Bitbox", NULL,         NULL,
		"y",    "Digital Bitbox", "no",         NULL,
		"y",    "Digital Bitbox", "yes",        NULL,
		"y",    "",               NULL,         NULL,
		"y",    "",               "no",         NULL,
		"y",    "",               "yes",        NULL,
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
	
    while (*run) {
   
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
   
    // test mnemonic       
    tests_format_send_cmd("seed", "{\"source\": \"silent answer fury celery kitten amused pudding struggle infant cake jealous ready curve more fame gown leave then client biology unusual lazy potato bubble\"}", PASSWORD_STAND); 
    if (tests_report_has("error")) { goto err; }
    
    tests_format_send_cmd("seed", "{\"source\": \"answer fury celery kitten amused pudding struggle infant cake jealous ready curve more fame gown leave then client biology unusual lazy potato bubble\"}", PASSWORD_STAND); 
    if (!tests_report_has(FLAG_ERR_MNEMO_CHECK)) { goto err; }
		
        
    tests_format_send_cmd("led", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }  
    tests_format_send_cmd("xpub", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; } 
    tests_format_send_cmd("seed", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; } 
    tests_format_send_cmd("sign", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; } 
    tests_format_send_cmd("reset", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }
    tests_format_send_cmd("backup", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }
    tests_format_send_cmd("random", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }
    tests_format_send_cmd("device", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; }
    tests_format_send_cmd("verifypass", "", PASSWORD_STAND); if (!tests_report_has(FLAG_ERR_INVALID_CMD)) { goto err; } 

    tests_fill_report("tests_backup_seed_xpub", "OK");
    return;

    err:
        tests_fill_report("tests_backup_seed_xpub", utils_read_decrypted_report());
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
        tests_fill_report("tests_device", utils_read_decrypted_report());
}


static void tests_input(void)
{
    int i;

    tests_reset();
    if (TEST_INTERNAL) {
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
    tests_format_send_cmd("sign", hash_sign2, PASSWORD_STAND);    if (!tests_report_has("echo")) { goto err; }
    tests_format_send_cmd("sign", hash_sign2, PASSWORD_STAND);    if (!tests_report_has(FLAG_ERR_BIP32_MISSING)) { goto err; }
    tests_format_send_cmd("seed", seed, PASSWORD_STAND);          if ( tests_report_has("error")) { goto err; }

    // test verifypass
    tests_format_send_cmd("verifypass", create, PASSWORD_STAND);  if ( tests_report_has("error"))              { goto err; }
    tests_format_send_cmd("backup", "erase", PASSWORD_STAND);     if ( tests_report_has("error"))              { goto err; }
    tests_format_send_cmd("backup", "list", PASSWORD_STAND);      if ( tests_report_has(VERIFYPASS_FILENAME))  { goto err; } 
    tests_format_send_cmd("verifypass", export, PASSWORD_STAND);  if ( tests_report_has("error"))              { goto err; } 
    tests_format_send_cmd("backup", "list", PASSWORD_STAND);      if (!tests_report_has(VERIFYPASS_FILENAME)) { goto err; } 
    
    // test echo
    tests_format_send_cmd("sign", hash_sign, PASSWORD_STAND);     if (!tests_report_has("echo")) { goto err; }
    tests_format_send_cmd("sign", hash_sign, PASSWORD_STAND);     if ( tests_report_has("echo"))  { goto err; } 
    tests_format_send_cmd("sign", hash_sign2, PASSWORD_STAND);    if (!tests_report_has("echo")) { goto err; } 
    tests_format_send_cmd("sign", hash_sign, PASSWORD_STAND);     if (!tests_report_has("echo")) { goto err; } 
    tests_format_send_cmd("sign", hash_sign, PASSWORD_STAND);     if ( tests_report_has("2FA"))   { goto err; } 
    tests_format_send_cmd("sign", hash_sign2, PASSWORD_STAND);    if (!tests_report_has("echo")) { goto err; } 
   
    // test hash length
    tests_format_send_cmd("sign", hash_sign3, PASSWORD_STAND);    if (!tests_report_has("echo")) { goto err; } 
    tests_format_send_cmd("sign", hash_sign3, PASSWORD_STAND);    if (!tests_report_has(FLAG_ERR_SIGN_LEN)) { goto err; } 

    
    // TODO test sign tx
    //char tx_sign[] = "{\"type\":\"transaction\", \"keypath\":\"m/\", \"data\":\"  \"}";
    // test deserialize
    // FLAG_ERR_DESERIALIZE
    // FLAG_ERR_BIP32_MISSING
    
    
    // test locked
    tests_format_send_cmd("device", "lock", PASSWORD_STAND);      if ( tests_report_has("error")) { goto err; }
    tests_format_send_cmd("sign", hash_sign, PASSWORD_STAND);     if (!tests_report_has("echo")) { goto err; } 
    tests_format_send_cmd("sign", hash_sign, PASSWORD_STAND);     if (!tests_report_has("2FA"))  { goto err; } 
    tests_format_send_cmd("seed", seed, PASSWORD_STAND);          if (!tests_report_has(FLAG_ERR_DEVICE_LOCKED)) { goto err; } 
    tests_format_send_cmd("verifypass", export, PASSWORD_STAND);  if (!tests_report_has(FLAG_ERR_DEVICE_LOCKED)) { goto err; } 
    tests_format_send_cmd("backup", "list", PASSWORD_STAND);      if (!tests_report_has(FLAG_ERR_DEVICE_LOCKED)) { goto err; } 

    tests_fill_report("tests_verifypass", "OK");
    return;
    
    err:
        tests_fill_report("tests_verifypass", utils_read_decrypted_report());
}


static void tests_run(void)
{
   
	tests_name();
    tests_password();
    tests_device();
    tests_random();
    tests_input();
    tests_backup_seed_xpub();
    tests_verifypass();
    tests_sign_speed();	
}


int main(void)
{
   
    // Test the C code API  
    TEST_INTERNAL = 1;
    random_init();
    memory_setup();
    memset(tests_report, 0, sizeof(tests_report));
    tests_run();
    printf("Internal API Result:\n%s\n\n", tests_report);
    
    // Live test of the HID API
    // The hidapi library must be installed:
    //     http://www.signal11.us/oss/hidapi/
    TEST_INTERNAL = 0;
    memset(tests_report, 0, sizeof(tests_report));
    memory_write_aeskey(tests_pwd, 4, PASSWORD_STAND);
    
    if (tests_hid_init() == ERROR) {
        printf("Not testing HID API. A device is not connected.\n\n");
        return 1;
    }
    
    tests_run();
    printf("HID API Result:\n%s\n\n", tests_report);

    return 0;
}
