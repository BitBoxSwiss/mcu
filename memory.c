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


#include <stdio.h>
#include <string.h>

#include "commander.h"
#include "memory.h"
#include "utils.h"
#include "sha2.h"
#ifndef TESTING
#include "ataes132.h"
#include <gpio.h>
#include <delay.h>
#include <ioport.h>
#endif


static uint8_t MEM_multipass_ = DEFAULT_multipass_;
static uint8_t MEM_erased_ = DEFAULT_erased_;
static uint8_t MEM_setup_ = DEFAULT_setup_;
static uint16_t MEM_delay_ = DEFAULT_delay_;

static uint16_t MEM_touch_timeout_ = DEFAULT_touch_timeout_;
static uint16_t MEM_touch_thresh_ = DEFAULT_touch_timeout_;
static uint8_t MEM_touch_enable_ = DEFAULT_enable_;
static uint8_t MEM_led_ = DEFAULT_led_;

static uint8_t MEM_aeskey_stand_[MEM_PAGE_LEN] = {0xFF};
static uint8_t MEM_aeskey_multi_[MEM_PAGE_LEN] = {0xFF};
static uint8_t MEM_name_[MEM_PAGE_LEN] = {'0'};
static uint8_t MEM_master_[MEM_PAGE_LEN] = {0xFF};
static uint8_t MEM_master_chain_[MEM_PAGE_LEN] = {0xFF};
static uint16_t MEM_mnemonic_[MEM_PAGE_LEN] = {0xFFFF};

const uint8_t MEM_PAGE_ERASE[] = { [0 ... MEM_PAGE_LEN] = 0xFF }; // EEPROM
const uint16_t MEM_PAGE_ERASE_2X[] = { [0 ... MEM_PAGE_LEN] = 0xFFFF };


// one time setup on factory install
void memory_setup(void)
{
    if (memory_setup_read()) {

        memory_erase();
        // ....
        // TODO key matching ataes to mcu, etc.
        // ....

        
#ifndef TESTING
		if (0) {
			// Lock Configuration Memory (only get one chance)
			// Lock command:              OP   MODE  PARAMETER1  PARAMETER2
			const uint8_t ataes_cmd[] = {0x0D, 0x02, 0x00, 0x00, 0x00, 0x00}; 
			
			// Return packet [Count(1) || Return Code (1) || CRC (2)]
			// Check that return code == 0x00 (success)
			uint8_t ataes_ret[4] = {0}; 
			aes_process(ataes_cmd, sizeof(ataes_cmd), ataes_ret, 4);
			if (ataes_ret[1]) {
				fill_report("lock_config", uint8_to_hex(ataes_ret, 4), ERROR);				
			} else {
				fill_report("lock_config", uint8_to_hex(ataes_ret, 4), SUCCESS);
			}
		}
#endif
		
        memory_setup_write(0x00);
        
    }
}


void memory_erase(void)
{
    memory_name("Digital Bitbox");
    memory_erased_write(DEFAULT_erased_);
    memory_multipass_write(DEFAULT_multipass_);
    memory_led_write(DEFAULT_led_);
    memory_touch_timeout_write(DEFAULT_touch_timeout_);
    memory_touch_thresh_write(DEFAULT_touch_thresh_);
    memory_touch_enable_write(DEFAULT_touch_enable_);
    memory_delay_iterate(DEFAULT_delay_);
    
    memory_aeskey_write((char *)MEM_PAGE_ERASE, MEM_PAGE_LEN, PASSWORD_STAND);
    memory_aeskey_write((char *)MEM_PAGE_ERASE, MEM_PAGE_LEN, PASSWORD_MULTI);
    memory_mnemonic(MEM_PAGE_ERASE_2X);
    memory_chaincode(MEM_PAGE_ERASE);
    memory_master(MEM_PAGE_ERASE);
}


void memory_clear_variables(void)
{
// TEST
#ifndef TESTING
    // Zero important variables in RAM on embedded MCU.
    // Do not clear for testing routines (i.e. not embedded).
    // Enable clearing if making a software wallet (variables should get loaded from an encrypted file).
    memcpy(MEM_name_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_stand_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_multi_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master_chain_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_mnemonic_, MEM_PAGE_ERASE_2X, MEM_PAGE_LEN*2);
#endif
}


static int memory_eeprom(const uint8_t *write_b, uint8_t *read_b, const int32_t addr, const uint16_t len)
{
    // read current memory
#ifndef TESTING
	aes_eeprom(len, addr, read_b, NULL);
#endif
    if (write_b){
#ifndef TESTING
        // skip writing if memory does not change
        if (read_b) {
            if (!memcmp(read_b, write_b, len)){
                return 1; 
            }
        }
        aes_eeprom(len, addr, read_b, write_b);
        if (read_b) {
            if (!memcmp(write_b, read_b, len)){
                return 1;
            } else { 
                // error 
                if (len>2) {
                    memcpy(read_b, MEM_PAGE_ERASE, len);
                }
                return 0;
            }
        }
#else        
        memcpy(read_b, write_b, len);
        (void) addr; 
        return 1; 
#endif
	} 
    return 1; 
}


uint8_t *memory_name(const char *name)
{
    uint8_t name_b[MEM_PAGE_LEN] = {0};
    if (strlen(name)) {
        memcpy(name_b,name,(strlen(name)>MEM_PAGE_LEN) ? MEM_PAGE_LEN : strlen(name));
        memory_eeprom(name_b, MEM_name_, MEM_NAME_ADDR, MEM_PAGE_LEN);
    } else {   
        memory_eeprom(NULL, MEM_name_, MEM_NAME_ADDR, MEM_PAGE_LEN);
    }
    return MEM_name_;
}


uint8_t *memory_master(const uint8_t *master)
{
    memory_eeprom(master, MEM_master_, 
                MEM_MASTER_BIP32_ADDR, MEM_PAGE_LEN);
    return MEM_master_;
}


uint8_t *memory_chaincode(const uint8_t *chain)
{
    memory_eeprom(chain, MEM_master_chain_, 
                MEM_MASTER_BIP32_CHAIN_ADDR, MEM_PAGE_LEN);
    return MEM_master_chain_;
}


uint16_t *memory_mnemonic(const uint16_t *idx)
{
    if (idx) {
        memory_eeprom((uint8_t *)idx, (uint8_t *)MEM_mnemonic_, 
                    MEM_MNEMONIC_BIP32_ADDR_0, MEM_PAGE_LEN);
        memory_eeprom((uint8_t *)idx + MEM_PAGE_LEN, 
                    (uint8_t *)MEM_mnemonic_ + MEM_PAGE_LEN,
                    MEM_MNEMONIC_BIP32_ADDR_1, MEM_PAGE_LEN);
    } else {
        memory_eeprom(NULL, (uint8_t *)MEM_mnemonic_, 
                    MEM_MNEMONIC_BIP32_ADDR_0, MEM_PAGE_LEN);
        memory_eeprom(NULL, (uint8_t *)MEM_mnemonic_ + MEM_PAGE_LEN, 
                    MEM_MNEMONIC_BIP32_ADDR_1, MEM_PAGE_LEN);
    }
    return MEM_mnemonic_;
}


int memory_aeskey_write(const char *password, int len, int id)
{
	int ret = 0;
    uint8_t password_b[MEM_PAGE_LEN];
	memset(password_b, 0, MEM_PAGE_LEN);
    
    // TEST really need a max condition if later hash it? check against python aes implementation
	//if (len < MEM_AESKEY_LEN_MIN || len > MEM_PAGE_LEN)
	if (len < MEM_AESKEY_LEN_MIN) {
        char errormsg[128];
		//sprintf(errormsg,"The password length must be between %i and %i characters.", MEM_AESKEY_LEN_MIN, MEM_PAGE_LEN);
		sprintf(errormsg,"The password length must be at least %i characters.", MEM_AESKEY_LEN_MIN);
		fill_report("password", errormsg, ERROR);
		return 0;
	}
    
	sha256_Raw((uint8_t *)password, len, password_b);
	sha256_Raw(password_b, MEM_PAGE_LEN, password_b);

    switch (id) {
        case PASSWORD_STAND:
            ret = memory_eeprom(password_b, MEM_aeskey_stand_, MEM_AESKEY_STAND_ADDR, MEM_PAGE_LEN);
            break;
        case PASSWORD_MULTI:
            ret = memory_eeprom(password_b, MEM_aeskey_multi_, MEM_AESKEY_MULTI_ADDR, MEM_PAGE_LEN);
            break;
    }

    if (ret) {
        return 1;
    } else { 
        fill_report("password", "Password saving error.", ERROR);
        return 0;
    }
}

uint8_t *memory_aeskey_read(int id)
{
    switch (id) {
        case PASSWORD_STAND:
            memory_eeprom(NULL, MEM_aeskey_stand_, MEM_AESKEY_STAND_ADDR, MEM_PAGE_LEN);
            return MEM_aeskey_stand_;

        case PASSWORD_MULTI:
            memory_eeprom(NULL, MEM_aeskey_multi_, MEM_AESKEY_MULTI_ADDR, MEM_PAGE_LEN);
            return MEM_aeskey_multi_;
    }
    return 0;
}


void memory_setup_write(const uint8_t setup)
{
    memory_eeprom(&setup, &MEM_setup_, MEM_SETUP_ADDR, 1);
}
uint8_t memory_setup_read(void)
{
    memory_eeprom(NULL, &MEM_setup_, MEM_SETUP_ADDR, 1);
    return MEM_setup_;
}


void memory_multipass_write(const uint8_t m)
{
    memory_eeprom(&m, &MEM_multipass_, MEM_MULTIPASS_ADDR, 1);
}
uint8_t memory_multipass_read(void)
{
    memory_eeprom(NULL, &MEM_multipass_, MEM_MULTIPASS_ADDR, 1);
    return MEM_multipass_;     
}


void memory_erased_write(const uint8_t erased)
{
    memory_eeprom(&erased, &MEM_erased_, MEM_ERASED_ADDR, 1);
}
uint8_t memory_erased_read(void)
{
    memory_eeprom(NULL, &MEM_erased_, MEM_ERASED_ADDR, 1);
    return MEM_erased_;     
}


void memory_led_write(const uint8_t led)
{
    memory_eeprom(&led, &MEM_led_, MEM_LED_ADDR, 1);
}
int memory_led_read(void)
{
    memory_eeprom(NULL, &MEM_led_, MEM_LED_ADDR, 1);
    return MEM_led_;       
}


// TEST 
void memory_touch_enable_write(const uint8_t e)
{
    memory_eeprom(&e, &MEM_touch_enable_, MEM_TOUCH_ENABLE_ADDR, 1);
}
uint8_t memory_touch_enable_read(void)
{
    memory_eeprom(NULL, &MEM_touch_enable_, MEM_TOUCH_ENABLE_ADDR, 1);
    return MEM_touch_enable_;
}


// TEST
// '0' resets, '1' increments delay counter
void memory_delay_iterate(const uint16_t d)
{
    uint16_t delay;
    if (d) {
        memory_eeprom(NULL, (uint8_t *)&MEM_delay_, MEM_DELAY_ADDR, 2);
        delay = MEM_delay_ + 1;
	} else {
        delay = 0;
    }
    
    // Force reset after too many failed attempts
    if (delay >= MAX_ATTEMPTS) {
        force_reset();
    } else {
        memory_eeprom((uint8_t *)&delay, (uint8_t *)&MEM_delay_, MEM_DELAY_ADDR, 2);
    }
}
    uint16_t memory_delay_read(void)
{
    memory_eeprom(NULL, (uint8_t *)&MEM_delay_, MEM_DELAY_ADDR, 2);
    return MEM_delay_;
}


void memory_touch_timeout_write(const uint16_t t)
{
    memory_eeprom((uint8_t *)&t, (uint8_t *)&MEM_touch_timeout_, MEM_TOUCH_TIMEOUT_ADDR, 2);
}
uint16_t memory_touch_timeout_read(void)
{
    memory_eeprom(NULL, (uint8_t *)&MEM_touch_timeout_, MEM_TOUCH_TIMEOUT_ADDR, 2);
    return MEM_touch_timeout_;
}


void memory_touch_thresh_write(const uint16_t t)
{
    memory_eeprom((uint8_t *)&t, (uint8_t *)&MEM_touch_thresh_, MEM_TOUCH_THRESH_ADDR, 2);
}
uint16_t memory_touch_thresh_read(void)
{
    memory_eeprom(NULL, (uint8_t *)&MEM_touch_thresh_, MEM_TOUCH_THRESH_ADDR, 2);
    return MEM_touch_thresh_;
}

