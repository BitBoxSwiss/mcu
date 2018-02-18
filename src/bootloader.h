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


#ifndef _BOOTLOADER_H_
#define _BOOTLOADER_H_


#include <stdint.h>


#define BOOT_SIG_M 4


typedef enum BOOT_OP_CODES {
    OP_WRITE = 'w',/* 0x77 */
    OP_ERASE = 'e',/* 0x65 */
    OP_BLINK = 'b',/* 0x62 */
    OP_REBOOT = 'r',/* 0x72 */
    OP_VERIFY = 's',/* 0x73 */
    OP_VERSION = 'v', /* 0x76 */
    OP_LOCK = 'l' /* 0x108 */
} BOOT_OP_CODES;

typedef enum BOOT_STATUS {
    OP_STATUS_ERR = 'Z',
    OP_STATUS_ERR_VERSION = 'V',
    OP_STATUS_ERR_LEN = 'N',
    OP_STATUS_ERR_MACRO = 'M',
    OP_STATUS_ERR_WRITE = 'W',
    OP_STATUS_ERR_CHECK = 'C',
    OP_STATUS_ERR_ABORT = 'A',
    OP_STATUS_ERR_ERASE = 'E',
    OP_STATUS_ERR_LOAD_FLAG = 'L',
    OP_STATUS_ERR_INVALID_CMD = 'I',
    OP_STATUS_OK = '0'
} BOOT_STATUS;


void bootloader_jump(void);
void bootloader_command(const char *command);


#endif
