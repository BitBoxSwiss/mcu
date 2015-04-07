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
#include <string.h>
#include <unistd.h>
#include "tests_internal.h"
#include "commander.h"
#include "utils.h"
#include "uECC.h"
#ifndef TESTING
#include "systick.h"
#include "mcu.h"
#endif


extern volatile uint16_t systick_current_time_ms;


static void tests_sign_speed(void)
{
	// N = 50 -> 7.5 sig/sec
	uint8_t sig[64], priv_key_0[32], priv_key_1[32], msg[256];
	float time_sec;
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
	time_sec = (float)(clock() - t) / CLOCKS_PER_SEC;
#else
    time_sec = systick_current_time_ms * 1000;
	NVIC_SetPriority(SysTick_IRQn, 15); // Reset lower priority
#endif
	
    if (res) {
		commander_fill_report("tests_sign_speed", "could not sign", ERROR);
	} else {
		char report[64];
		sprintf(report, "%0.2f sig/s", N * 2 / time_sec);
		commander_fill_report("tests_sign_speed", report, SUCCESS);
	}
	
	return;
}


static void tests_backup(void)
{
    //commander("{\"device\": \"serial\"}");
    utils_send_cmd("{\"device\":\"serial\"}", PASSWORD_STAND); 
}


// TODO remove for production
static void tests_mempass(void)
{
    int r[8] = {0};
    char c[3] = {0};
    sscanf(__TIME__, "%d:%d:%d", &r[0], &r[1], &r[2]);
    sscanf(__DATE__, "%c%c%c %d ", &c[0], &c[1], &c[2], &r[3]);
    r[4] = c[0];
    r[5] = c[1];
    r[6] = c[2];
    r[7] = __LINE__ % 1028;

#ifdef TESTING
    printf("debug mempass  %d \n", __LINE__);
    printf("debug mempass  %s \n", __DATE__);
    printf("debug mempass  %s \n", __TIME__);
    printf("debug mempass %d %d %d\n", r[0], r[1], r[2]);
    printf("debug mempass %d %d %d %d %d\n", r[3], r[4], r[5], r[6], r[7]);
#else	
	uint8_t mempass[88] = {0};
	uint8_t *mp = mempass;
	// obfuscate mempass location
    memcpy(mp +  0, (uint32_t *)IFLASH0_ADDR + r[0] * r[0], 8);
	memcpy(mp +  8, (uint32_t *)IFLASH0_ADDR + r[0] * r[1], 8);
	memcpy(mp + 16, (uint32_t *)IFLASH0_ADDR + r[0] * r[2], 8);
	memcpy(mp + 24, (uint32_t *)IFLASH0_ADDR + r[1] * r[1], 8);
	memcpy(mp + 32, (uint32_t *)IFLASH0_ADDR + r[1] * r[2], 8);
	memcpy(mp + 40, (uint32_t *)IFLASH0_ADDR + r[2] * r[2], 8);
	memcpy(mp + 48, (uint32_t *)IFLASH0_ADDR + r[0] * r[3], 8);
	memcpy(mp + 56, (uint32_t *)IFLASH0_ADDR + r[0] * r[4], 8);
	memcpy(mp + 64, (uint32_t *)IFLASH0_ADDR + r[0] * r[5], 8);
	memcpy(mp + 72, (uint32_t *)IFLASH0_ADDR + r[0] * r[6], 8);
	memcpy(mp + 80, (uint32_t *)IFLASH0_ADDR + r[7], 8);
    
    commander_fill_report("tests_mempass", uint8_to_hex(mempass, sizeof(mempass)), SUCCESS);

#endif
}


void tests_internal(void)
{
    tests_mempass();
    tests_backup();
	tests_sign_speed();	
}
