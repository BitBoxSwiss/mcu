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

#include "memory.h"
#include "commander.h"
#include "sha2.h"
#ifndef NOT_EMBEDDED
#include "ataes132.h"
#include <gpio.h>
#include <delay.h>
#include <ioport.h>
#endif


static uint16_t MEM_delay_;
static uint16_t MEM_touch_timeout_;
static uint16_t MEM_touch_thresh_;
static uint8_t MEM_touch_enable_;
static uint8_t MEM_setup_;
static uint8_t MEM_erased_;
static uint8_t MEM_led_;

static uint8_t MEM_name_[MEM_PAGE_LEN];
static uint8_t MEM_aeskey_[MEM_PAGE_LEN];
static uint8_t MEM_mnemonic_electrum_[MEM_PAGE_LEN+1];
static uint8_t MEM_master_electrum_[MEM_PAGE_LEN];
static uint8_t MEM_master_bip32_[MEM_PAGE_LEN];
static uint8_t MEM_master_bip32_chain_[MEM_PAGE_LEN];
static uint16_t MEM_mnemonic_bip32_[MEM_PAGE_LEN];

const uint8_t MEM_PAGE_ERASE[] = { [0 ... MEM_PAGE_LEN] = 0xFF }; // EEPROM
const uint16_t MEM_PAGE_ERASE_2X[] = { [0 ... MEM_PAGE_LEN] = 0xFFFF };


void memory_setup(void)
{
    memory_setup_write(0xFF); // necessary for initializing global variables using non-embedded code
    memory_erase();
    // ....
    // TODO aes config setup, key matching to mcu, etc.
    // ....
    memory_setup_write(0x00);
}


void memory_erase(void)
{
    memory_name("Digital Bitbox");
    memory_erased_write(DEFAULT_erased_);
    memory_led_write(DEFAULT_led_);
    memory_touch_timeout_write(DEFAULT_touch_timeout_);
    memory_touch_thresh_write(DEFAULT_touch_thresh_);
    memory_touch_enable_write(DEFAULT_touch_enable_);
    memory_delay_iterate(0);
    
    memory_aeskey_write((char *)MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memory_electrum_mnemonic((char *)MEM_PAGE_ERASE);
    memory_electrum_master(MEM_PAGE_ERASE);
	
    memory_bip32_mnemonic(MEM_PAGE_ERASE_2X);
    memory_bip32_chaincode(MEM_PAGE_ERASE);
    memory_bip32_master(MEM_PAGE_ERASE);
}


void memory_fill_variables(void)
{
    // load variables into memory
    MEM_touch_timeout_ = memory_touch_timeout_read();
    MEM_touch_thresh_ = memory_touch_thresh_read();
    MEM_touch_enable_ = memory_touch_enable_read();
    MEM_erased_ = memory_erased_read();
    MEM_setup_ = memory_setup_read();
    MEM_delay_ = memory_delay_read();
    MEM_led_ = memory_led_read();
    
    memory_name("");
    memory_aeskey_read();
    memory_bip32_master(NULL);
    memory_bip32_mnemonic(NULL);
    memory_bip32_chaincode(NULL);
    memory_electrum_master(NULL);
    memory_electrum_mnemonic(NULL);
}


void memory_clear_variables(void)
{
// TEST
#ifndef NOT_EMBEDDED
    // zero important variables in RAM on embedded MCU
    // do not clear for testing routines (i.e. not embedded)
    // enable this function if making a software wallet (load variables from a file)
    memcpy(MEM_name_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_mnemonic_electrum_, MEM_PAGE_ERASE, MEM_PAGE_LEN+1);
    memcpy(MEM_master_electrum_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master_bip32_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master_bip32_chain_, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_mnemonic_bip32_, MEM_PAGE_ERASE_2X, MEM_PAGE_LEN*2);
#endif
}


static int memory_page(const uint8_t *write_b, uint8_t *read_b, const int32_t addr)
{
    if (write_b){
        if (!memory_setup_read()){ // always write on setup
            if (!memcmp(read_b, write_b, MEM_PAGE_LEN)){
                return 1; 
           }
        }
#ifndef NOT_EMBEDDED
        aes_eeprom(MEM_PAGE_LEN, addr, read_b, write_b);
        if (!memcmp(write_b, read_b, MEM_PAGE_LEN)){
            return 1;
        } else { // error 
            memcpy(read_b, MEM_PAGE_ERASE, MEM_PAGE_LEN);
            return 0;
        }
#else        
        memcpy(read_b, write_b, MEM_PAGE_LEN);
        (void) addr; 
        return 1; 
#endif
	} else { // return stored value 
#ifndef NOT_EMBEDDED
		aes_eeprom(MEM_PAGE_LEN, addr, read_b, NULL);
#endif
        return 1; 
	}
}


uint8_t *memory_name(const char *name)
{
    uint8_t name_b[MEM_PAGE_LEN] = {0};
    if (strlen(name)) {
        memcpy(name_b,name,(strlen(name)>MEM_PAGE_LEN) ? MEM_PAGE_LEN : strlen(name));
        memory_page(name_b, MEM_name_, MEM_NAME_ADDR);
    } else {   
        memory_page(NULL, MEM_name_, MEM_NAME_ADDR);
    }
    return MEM_name_;
}


uint8_t *memory_electrum_master(const uint8_t *master)
{
    memory_page(master, MEM_master_electrum_, MEM_MASTER_ELECTRUM_ADDR);
    return MEM_master_electrum_;
}


uint8_t *memory_bip32_master(const uint8_t *master)
{
    memory_page(master, MEM_master_bip32_, MEM_MASTER_BIP32_ADDR);
    return MEM_master_bip32_;
}


uint8_t *memory_bip32_chaincode(const uint8_t *chain)
{
    memory_page(chain, MEM_master_bip32_chain_, MEM_MASTER_BIP32_CHAIN_ADDR);
    return MEM_master_bip32_chain_;
}


uint16_t *memory_bip32_mnemonic(const uint16_t *idx)
{
    if (idx) {
        memory_page((uint8_t *)idx, (uint8_t *)MEM_mnemonic_bip32_, MEM_MNEMONIC_BIP32_ADDR_0);
        memory_page((uint8_t *)idx + MEM_PAGE_LEN, (uint8_t *)MEM_mnemonic_bip32_ + MEM_PAGE_LEN, MEM_MNEMONIC_BIP32_ADDR_1);
    } else {
        memory_page(NULL, (uint8_t *)MEM_mnemonic_bip32_, MEM_MNEMONIC_BIP32_ADDR_0);
        memory_page(NULL, (uint8_t *)MEM_mnemonic_bip32_ + MEM_PAGE_LEN, MEM_MNEMONIC_BIP32_ADDR_1);
    }
    return MEM_mnemonic_bip32_;
}


char *memory_electrum_mnemonic(const char *seed_hex)
{
    memory_page((uint8_t *)seed_hex, MEM_mnemonic_electrum_, MEM_MNEMONIC_ELECTRUM_ADDR);
    MEM_mnemonic_electrum_[MEM_PAGE_LEN] = '\0';
    return((char *)MEM_mnemonic_electrum_);
}


int memory_aeskey_write(const char *password, int len)
{
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

    if (memory_page(password_b, MEM_aeskey_, MEM_AESKEY_ADDR)) {
        fill_report("password", "success", SUCCESS);
        return 1;
    } else { 
        fill_report("password", "Password saving error.", ERROR);
        return 0;
    }
}


uint8_t *memory_aeskey_read(void)
{
    memory_page(NULL, MEM_aeskey_, MEM_AESKEY_ADDR);
    return MEM_aeskey_;
}


static void memory_byte_write(const uint32_t addr, const uint8_t *byte)
{
#ifndef NOT_EMBEDDED
	aes_eeprom(1, addr, NULL, byte);
#else
    (void)addr;
    (void)byte;
#endif
}


static void memory_uint8_t_read(const uint32_t addr, uint8_t *mem)
{
#ifndef NOT_EMBEDDED
	aes_eeprom(1, addr, mem, NULL);
#else
    (void)addr;
    (void)mem;
#endif
}


static void memory_uint16_t_read(const uint32_t addr, uint16_t *mem)
{
#ifndef NOT_EMBEDDED
	uint8_t b[2];
	aes_eeprom(2, addr, b, NULL);
	*mem = b[0] + (b[1] << 8);
#else
    (void)addr;
    (void)mem;
#endif
}


void memory_setup_write(const uint8_t setup)
{
    MEM_setup_ = setup;
    memory_byte_write(MEM_ERASED_ADDR, &setup);
}


uint8_t memory_setup_read(void)
{
    memory_uint8_t_read(MEM_ERASED_ADDR, &MEM_setup_);
    return MEM_setup_;     
}


void memory_erased_write(const uint8_t erased)
{
    MEM_erased_ = erased;
    memory_byte_write(MEM_ERASED_ADDR, &erased);
}


uint8_t memory_erased_read(void)
{
    memory_uint8_t_read(MEM_ERASED_ADDR, &MEM_erased_);
    return MEM_erased_;     
}


void memory_led_write(const uint8_t led)
{
    MEM_led_ = led;          
    memory_byte_write(MEM_LED_ADDR, &led);
}


int memory_led_read(void)
{
    memory_uint8_t_read(MEM_LED_ADDR, &MEM_led_);
    return MEM_led_;       
}


// '0' resets, '1' increments delay counter
void memory_delay_iterate(const uint16_t d)
{
    if (d) {
        memory_uint16_t_read(MEM_DELAY_ADDR, &MEM_delay_);
        MEM_delay_++;
	} else {
        MEM_delay_ = 0;
    }
    uint8_t delay_0 = (MEM_delay_ & 0x00ff);
	uint8_t delay_1 = (MEM_delay_ & 0xff00) >> 8;
    memory_byte_write(MEM_DELAY_ADDR, &delay_0);
    memory_byte_write(MEM_DELAY_ADDR+1, &delay_1); 
}


uint16_t memory_delay_read(void)
{
    memory_uint16_t_read(MEM_DELAY_ADDR, &MEM_delay_);
    return MEM_delay_;
}


void memory_touch_timeout_write(const uint16_t t)
{
    MEM_touch_timeout_ = t;     
	uint8_t timeout_0 = (t & 0x00ff);
	uint8_t timeout_1 = (t & 0xff00) >> 8;
    memory_byte_write(MEM_TOUCH_TIMEOUT_ADDR, &timeout_0);
    memory_byte_write(MEM_TOUCH_TIMEOUT_ADDR+1, &timeout_1); 
}


uint16_t memory_touch_timeout_read(void)
{
    memory_uint16_t_read(MEM_TOUCH_TIMEOUT_ADDR, &MEM_touch_timeout_);
    return MEM_touch_timeout_;
}


void memory_touch_thresh_write(const uint16_t t)
{
    MEM_touch_thresh_ = t;      
	uint8_t thresh_0 = (t & 0x00ff);
	uint8_t thresh_1 = (t & 0xff00) >> 8;
    memory_byte_write(MEM_TOUCH_THRESH_ADDR, &thresh_0);
    memory_byte_write(MEM_TOUCH_THRESH_ADDR + 1, &thresh_1);
}


uint16_t memory_touch_thresh_read(void)
{
    memory_uint16_t_read(MEM_TOUCH_THRESH_ADDR, &MEM_touch_thresh_);
    return MEM_touch_thresh_;
}


// TEST 
void memory_touch_enable_write(const uint8_t e)
{
    MEM_touch_enable_ = e;  
    memory_byte_write(MEM_TOUCH_ENABLE_ADDR, &e);
}


uint8_t memory_touch_enable_read(void)
{
    memory_uint8_t_read(MEM_TOUCH_ENABLE_ADDR, &MEM_touch_enable_);
    return MEM_touch_enable_;
}

