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



#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <stdint.h>

#define MEM_PAGE_LEN                32
#define MEM_AESKEY_LEN_MIN			4

// User Zones: 0x0000 to 0x0FFF
#define MEM_LED_ADDR			    0x0020// Zone 0
#define MEM_TOUCH_TIMEOUT_ADDR	   	0x0022
#define MEM_TOUCH_THRESH_ADDR	    0x0024
#define MEM_TOUCH_ENABLE_ADDR   	0x0026
#define MEM_ERASED_ADDR 	    	0x0028
#define MEM_SETUP_ADDR      		0x0030
#define MEM_DELAY_ADDR      		0x0032
#define MEM_UNLOCKED_ADDR      		0x0034
#define MEM_AESKEY_MEMSEED_ADDR		0x0036
#define MEM_NAME_ADDR   			0x0100// Zone 1
#define MEM_MASTER_BIP32_ADDR		0x0200// Zone 2
#define MEM_MASTER_BIP32_CHAIN_ADDR	0x0300// Zone 3
#define MEM_MNEMONIC_BIP32_ADDR_0	0x0400// Zone 4
#define MEM_MNEMONIC_BIP32_ADDR_1	0x0500// Zone 5
#define MEM_AESKEY_STAND_ADDR		0x0600// Zone 6
#define MEM_AESKEY_VERIFY_ADDR		0x0700// Zone 7

// Default settings
#define DEFAULT_unlocked_           0xFF
#define DEFAULT_erased_             0xFF
#define DEFAULT_setup_              0xFF
#define DEFAULT_delay_              0
#define DEFAULT_led_                0
#define DEFAULT_touch_timeout_      3000// msec
#define DEFAULT_touch_thresh_       50


typedef enum PASSWORD_ID { 
    PASSWORD_STAND, 
    PASSWORD_VERIFY, 
    PASSWORD_MEMORY, 
    PASSWORD_2FA,    /* only kept in RAM */ 
    PASSWORD_NONE    /* keep last */
} PASSWORD_ID;


void memory_erase(void);
void memory_setup(void);
void memory_clear_variables(void);
void memory_mempass(void);

int memory_write_aeskey(const char *password, int len, int id);
uint8_t *memory_read_aeskey(int id);
uint8_t *memory_name(const char *name);
uint8_t *memory_master(const uint8_t *master_priv_key);
uint8_t *memory_chaincode(const uint8_t *chain_code);
uint16_t *memory_mnemonic(const uint16_t *index);

uint16_t memory_read_delay(void);
uint8_t *memory_read_memseed(void);
uint16_t memory_read_touch_timeout(void);
uint16_t memory_read_touch_thresh(void);
uint8_t memory_read_erased(void);
uint8_t memory_read_setup(void);
uint8_t memory_read_unlocked(void);
int memory_read_led(void);

void memory_delay_iterate(const uint16_t d);
void memory_write_memseed(const uint8_t *s);
void memory_write_touch_timeout(const uint16_t t);
void memory_write_touch_thresh(const uint16_t t);
void memory_write_erased(const uint8_t erase);
void memory_write_setup(const uint8_t setup);
void memory_write_unlocked(const uint8_t u);
void memory_write_led(const uint8_t led);


#endif  // _MEMORY_H_
