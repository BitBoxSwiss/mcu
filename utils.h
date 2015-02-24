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


#ifndef _UTILS_H_
#define _UTILS_H_


#include <stdint.h>
#include <stddef.h>
#include "memory.h"

#define TO_UINT8_HEX_BUF_LEN 2048


uint8_t *hex_to_uint8(const char *str);
char *uint8_to_hex(const uint8_t *bin, size_t l);
#ifdef TESTING
uint8_t *utils_double_sha256(const uint8_t *msg, uint32_t msg_len);
void utils_print_report(const char *report, PASSWORD_ID dec_id);
void utils_send_cmd(const char *instruction, PASSWORD_ID enc_id, PASSWORD_ID dec_id);
void utils_send_cmd_x2(const char *instruction, PASSWORD_ID enc_id, PASSWORD_ID dec_id);
#endif


#endif
