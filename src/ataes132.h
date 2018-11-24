/*

 The MIT License (MIT)

 Copyright (c) 2015-2017 Douglas J. Bakkum

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


#ifndef _AES132_H_
#define _AES132_H_


#include <stdint.h>


#define ATAES_RAND_LEN 0x10
#define ATAES_CMD_RAND 0x02
#define ATAES_CMD_LOCK 0x0D

#ifdef TESTING
#define ATAES_EEPROM_LEN 0x1000
#define ATAES_EEPROM_ZONE_LEN 0x100
#define ATAES_EEPROM_ZONE_NUM (ATAES_EEPROM_LEN / ATAES_EEPROM_ZONE_LEN)
uint8_t *ataes_eeprom_simulation_report(void);
void ataes_eeprom_simulation_clear(void);
void ataes_eeprom_simulation_write(const uint8_t *data, uint16_t start, uint16_t len);
#endif
int ataes_process(uint8_t const *command, uint16_t cmd_len, uint8_t *response_block,
                  uint16_t response_len);
int ataes_eeprom(uint16_t LEN, uint32_t ADDR, uint8_t *userdata_read,
                 const uint8_t *userdata_write);


#endif
