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

#include "commander.h"
#include "ataes132.h"
#include "delay.h"
#include "utils.h"
#include "mcu.h"


#define aes_build_word_address(p_u8, addr) \
do {\
	p_u8[0] = (uint8_t)(addr >> 8);\
	p_u8[1] = (uint8_t)(addr & 0xFF);\
} while (0)



void aes_init(void)
{
	twi_options_t opts = {
		.master_clk = sysclk_get_cpu_hz(),
		.speed = AES_TWI_SPEED,
		.smbus = 0
	};

	sysclk_enable_peripheral_clock(AES_TWI_ID);
	twi_master_init(AES_TWI, &opts);
}


void CalculateCrc(uint8_t length, const uint8_t *data, uint8_t *crc) 
{ 
	 uint8_t counter; 
	 uint8_t crcLow = 0, crcHigh = 0, crcCarry; 
	 uint8_t polyLow = 0x05, polyHigh = 0x80; 
	 uint8_t shiftRegister; 
	 uint8_t dataBit, crcBit; 
 
	 for (counter = 0; counter < length; counter++) { 
		 for (shiftRegister = 0x80; shiftRegister > 0x00; shiftRegister >>= 1) { 
		 dataBit = (data[counter] & shiftRegister) ? 1 : 0; 
		 crcBit = crcHigh >> 7; 
 
		 // Shift CRC to the left by 1. 
		 crcCarry = crcLow >> 7; 
		 crcLow <<= 1; 
		 crcHigh <<= 1; 
		 crcHigh |= crcCarry; 
 
		 if ((dataBit ^ crcBit) != 0) { 
			 crcLow ^= polyLow; 
			 crcHigh ^= polyHigh; 
			 } 
		 } 
	 } 
	 crc[0] = crcHigh; 
	 crc[1] = crcLow; 
}



uint8_t aes_eeprom_write(uint32_t u32_start_address, uint16_t u16_length,
uint8_t const *p_wr_buffer)
{
	
	twi_package_t twi_package;

	/* Configure the data packet to be transmitted */
	twi_package.chip = AES_DEVICE_ADDR;
	aes_build_word_address(twi_package.addr, u32_start_address);
	twi_package.addr_length = AES_MEM_ADDR_LEN;
	twi_package.buffer = (uint8_t *)p_wr_buffer;
	twi_package.length = u16_length;

	return twi_master_write(AES_TWI, &twi_package);

}


uint32_t aes_eeprom_read(uint32_t u32_start_address, uint16_t u16_length,
uint8_t *p_rd_buffer)
{
	twi_package_t twi_package;

	/* Configure the data packet to be received */
	twi_package.chip = AES_DEVICE_ADDR;
	aes_build_word_address(twi_package.addr, u32_start_address);
	twi_package.addr_length = AES_MEM_ADDR_LEN;
	twi_package.buffer = p_rd_buffer;
	twi_package.length = u16_length;

	return twi_master_read(AES_TWI, &twi_package);
	
}




//TODO  need to lock LockConfig register to get a random number
void aes_process(uint8_t const *command, uint16_t cmd_len, 
uint8_t *response_block, uint16_t response_len)
{
	uint8_t i;
	uint8_t crc[2];

	//uint8_t command_block[cmd_len+3];
	uint8_t command_block[cmd_len + 3];
	command_block[0] = cmd_len + 3;
	for (i = 0; i < cmd_len; i++) {
		command_block[i + 1] = command[i];
	}
	
    // CRC done on [Count | Packet] bytes
	CalculateCrc(cmd_len + 1, command_block, crc); 
	
	command_block[cmd_len + 1] = crc[0];
	command_block[cmd_len + 2] = crc[1];
	
	uint32_t ret = 0;
	uint8_t aes_status = 0;
	

// TODO use STATUS to know if command succeeded / finished
// should be read before sending commands and receiving responses

	ret = aes_eeprom_read(AES_MEM_ADDR_STATUS, 1, &aes_status);

	// write command block
	ret = aes_eeprom_write(AES_MEM_ADDR_RESET, 1, 0);
	ret = aes_eeprom_read(AES_MEM_ADDR_STATUS, 1, &aes_status);

	ret = aes_eeprom_write(AES_MEM_ADDR_IO, cmd_len + 3, command_block);
	ret = aes_eeprom_read(AES_MEM_ADDR_STATUS, 1, &aes_status);
	
	// read response block
	ret = aes_eeprom_write(AES_MEM_ADDR_RESET, 1, 0);
	ret = aes_eeprom_read(AES_MEM_ADDR_STATUS, 1, &aes_status);

	ret = aes_eeprom_read(AES_MEM_ADDR_IO, response_len, response_block); 
	ret = aes_eeprom_read(AES_MEM_ADDR_STATUS, 1, &aes_status);


/* TODO: ADD CRC checking of response packet */

}


// Pass NULL to read only or write only
void aes_eeprom(uint16_t LEN, uint32_t ADDR, uint8_t *userdata_read, 
const uint8_t *userdata_write)
{
	
	int ret;
	char message[64];
	
	if (userdata_write != NULL) {
		ret = aes_eeprom_write(ADDR, LEN, userdata_write);
		if (ret) {
			sprintf(message, "EEPROM write error %i.", ret);
			fill_report("eeprom", message, ERROR);
			return;
		}
		delay_ms(100); // some delay is required to avoid errors - better to look at STATUS	
	}
		
	if (userdata_read != NULL) {
		ret = aes_eeprom_read(ADDR, LEN, userdata_read);
		if (ret) {
			sprintf(message, "EEPROM read error %i.", ret);
			fill_report("eeprom", message, ERROR);
			return;
		}
	}
}


/*
Using the Command Memory Buffer

The Host should write a single byte to the IO Address Reset Register before writing a new command block to the
Command Memory Buffer. This resets the buffer address pointer to the base address. The Host then writes the
ATAES132 command block to the buffer using one or more standard SPI or I2C Write commands. After the entire
command block is written by the Host microcontroller, the ATAES132 checks the 16-bit Checksum and executes
the command. The Host should read the STATUS Register to determine if an error occurred or if the response is
ready to be read.

If a Checksum error occurs, then the buffer address pointer must be reset by the Host before the command block
is retransmitted. If no errors occur, then the response can be read from the Response Memory Buffer, as
described in Appendix D.2.10, Using the Response Memory Buffer (see Appendix G, Understanding the STATUS
Register for examples).

The Command Memory Buffer size is 64 bytes. If the Host writes more than 64 bytes to the buffer, it will cause 
buffer overflow error. If the Host hardware must send more bytes to the ATAES132 than are required to transmit a
command block (due to Host hardware limitations), then all bytes transmitted after the block Checksum must
contain 0xFF.
*/
	
/*
Using the Response Memory Buffer

After an ATAES132 command is executed, the RRDY bit of the STATUS Register is set to 1b to indicate that a
new response is available in the Response Memory Buffer. The Host reads the response block from the buffer
using one or more standard SPI or I2C Read commands. After the entire response block is read, the Host
microcontroller checks the 16-bit Checksum.

If a Checksum error occurs, then the buffer address pointer must be reset by the Host before the response block
is reread. If the Host reads more bytes from the response buffer than necessary to retrieve the block, then all
bytes after the block Checksum will contain 0xFF (see Appendix G for examples). The Response Memory Buffer
size is 64 bytes.

*/



/* MEMORY MAP
0000h-0FFFh User Memory (See Appendix C, User Memory Map)			[0 - 4095 => 4096 bytes] [256 bytes per zone; 16 zones]
1000h-EFFFh Reserved
F000h-F05Fh Configuration Memory - Device Config (See Appendix E, Configuration Memory Map)		[serial # F000-F007]
F060h-F07Fh Configuration Memory - CounterConfig (See Appendix E)
F080h-F0BFh Configuration Memory - KeyConfig (See Appendix E)
F0C0h-F0FFh Configuration Memory - ZoneConfig (See Appendix E)
F100h-F17Fh Configuration Memory - Counters (See Appendix E)
F180h-F1DFh Configuration Memory - FreeSpace (See Appendix E)		[61824 - 61919 => 96 bytes]
F1E0h-F1FFh Configuration Memory - SmallZone (See Appendix E)		[61920 - 61951 => 32 bytes]
F200h-F2FFh Key Memory (See Appendix F, Key Memory Map)
F300h-FDFFh Reserved
FE00h Command / Response Memory Buffer (See Appendix D, Command Memory Map)
FE01h-FFDFh Reserved
FFE0h I/O Address Reset
FFE1h-FFEFh Reserved
FFF0h STATUS Register
FFF1h-FFFFh Reserved
*/
