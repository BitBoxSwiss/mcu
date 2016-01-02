/*

 The MIT License (MIT)

 Copyright (c) 2015-2016 Douglas J. Bakkum

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

#include "ataes132.h"
#include "delay.h"
#include "flags.h"
#include "mcu.h"


#define ataes_build_word_address(p_u8, addr) \
do {\
    p_u8[0] = (uint8_t)(addr >> 8);\
    p_u8[1] = (uint8_t)(addr & 0xFF);\
} while (0)


static void ataes_calculate_crc(uint8_t length, const uint8_t *data, uint8_t *crc)
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


static uint8_t ataes_eeprom_write(uint32_t u32_start_address, uint16_t u16_length,
                                  uint8_t *p_wr_buffer)
{
    twi_package_t twi_package;
    twi_package.chip = AES_DEVICE_ADDR;
    ataes_build_word_address(twi_package.addr, u32_start_address);
    twi_package.addr_length = AES_MEM_ADDR_LEN;
    twi_package.buffer = p_wr_buffer;
    twi_package.length = u16_length;
    return twi_master_write(AES_TWI, &twi_package);
}


static uint32_t ataes_eeprom_read(uint32_t u32_start_address, uint16_t u16_length,
                                  uint8_t *p_rd_buffer)
{
    twi_package_t twi_package;
    twi_package.chip = AES_DEVICE_ADDR;
    ataes_build_word_address(twi_package.addr, u32_start_address);
    twi_package.addr_length = AES_MEM_ADDR_LEN;
    twi_package.buffer = p_rd_buffer;
    twi_package.length = u16_length;
    return twi_master_read(AES_TWI, &twi_package);
}


void ataes_init(void)
{
    twi_options_t opts = {
        .master_clk = sysclk_get_cpu_hz(),
        .speed = AES_TWI_SPEED,
        .smbus = 0
    };
    sysclk_enable_peripheral_clock(AES_TWI_ID);
    twi_master_init(AES_TWI, &opts);
}


/*
 Sending command:     OP   MODE  PARAMETER1  PARAMETER2  DATA ... DATA
                     0xXX  0xXX  0xXX  0xXX  0xXX  0xXX  0xXX ... 0xXX
 Return block:       [Count(1) || Return Code (1) | Data(...) || CRC (2)]
*/
int ataes_process(uint8_t const *command, uint16_t cmd_len,
                  uint8_t *response_block, uint16_t response_len)
{
    uint32_t ret = 0;
    uint8_t ataes_status = 0;
    uint8_t delay = 2; // msec
    uint8_t timeout = 10; // counts
    uint8_t cnt, i, crc[2];

    uint8_t command_block[cmd_len + 3];
    command_block[0] = cmd_len + 3;
    for (i = 0; i < cmd_len; i++) {
        command_block[i + 1] = command[i];
    }

    // CRC on [Count | Packet] bytes
    ataes_calculate_crc(cmd_len + 1, command_block, crc);

    command_block[cmd_len + 1] = crc[0];
    command_block[cmd_len + 2] = crc[1];

    memset(response_block, 0, response_len);

    // Check if awake
    cnt = 0;
    while (1) {
        ret = ataes_eeprom_read(AES_MEM_ADDR_STATUS, 1, &ataes_status);
        if (!ataes_status && !ret) {
            break;
        }
        if ((ataes_status & 0x40) && !ret) {
            break;
        }
        if (cnt++ > timeout) {
            return DBB_ERROR;
        }
        delay_ms(delay);
    }

    // Reset memory pointer
    cnt = 0;
    while (1) {
        ret = ataes_eeprom_write(AES_MEM_ADDR_RESET, 1, 0);
        if (!ret) {
            break;
        } else if (cnt++ > timeout) {
            return DBB_ERROR;
        }
    }

    // Check if ready
    cnt = 0;
    while (1) {
        ret = ataes_eeprom_read(AES_MEM_ADDR_STATUS, 1, &ataes_status);
        if (!ataes_status && !ret) {
            break;
        }
        if ((ataes_status & 0x40) && !ret) {
            break;
        } else if (cnt++ > timeout) {
            return DBB_ERROR;
        }
        delay_ms(delay);
    }

    // Write command block
    cnt = 0;
    while (1) {
        ret = ataes_eeprom_write(AES_MEM_ADDR_IO, cmd_len + 3, command_block);
        if (!ret) {
            break;
        } else if (cnt++ > timeout) {
            return DBB_ERROR;
        }
    }

    // Check if data is available to read (0x40)
    cnt = 0;
    while (1) {
        ret = ataes_eeprom_read(AES_MEM_ADDR_STATUS, 1, &ataes_status);
        if ((ataes_status & 0x40) && !ret) {
            break;
        }
        if (cnt++ > timeout) {
            return DBB_ERROR;
        }
        delay_ms(delay);
    }

    // Reset memory pointer
    cnt = 0;
    while (1) {
        ret = ataes_eeprom_write(AES_MEM_ADDR_RESET, 1, 0);
        if (!ret) {
            break;
        } else if (cnt++ > timeout) {
            return DBB_ERROR;
        }
    }

    // Read response block - does not change STATUS register
    cnt = 0;
    while (1) {
        ret = ataes_eeprom_read(AES_MEM_ADDR_IO, response_len, response_block);
        if (!ret) {
            break;
        } else if (cnt++ > timeout) {
            return DBB_ERROR;
        }
    }

    return DBB_OK;
}


// Pass NULL to read only or write only
int ataes_eeprom(uint16_t LEN, uint32_t ADDR, uint8_t *userdata_read,
                 uint8_t *userdata_write)
{
    int ret;
    uint8_t ataes_status = 0;
    uint8_t delay = 2; // msec
    uint8_t timeout = 10; // counts
    uint8_t cnt = 0;

    if (userdata_write != NULL) {
        ret = ataes_eeprom_write(ADDR, LEN, userdata_write);
        if (ret) {
            return DBB_ERROR;
        }
        while (1) {
            ret = ataes_eeprom_read(AES_MEM_ADDR_STATUS, 1, &ataes_status);
            if (!(ataes_status & 0x81) && !ret) { // 0x81 = no error and device ready
                break;
            } else if (cnt++ > timeout) {
                return DBB_ERROR;
            }
            delay_ms(delay);
        }
    }

    if (userdata_read != NULL) {
        ret = ataes_eeprom_read(ADDR, LEN, userdata_read);
        if (ret) {
            return DBB_ERROR;
        }
        while (1) {
            ret = ataes_eeprom_read(AES_MEM_ADDR_STATUS, 1, &ataes_status);
            if (!ataes_status && !ret) {
                break;
            } else if (cnt++ > timeout) {
                return DBB_ERROR;
            }
            delay_ms(delay);
        }
    }

    return DBB_OK;
}

