/*

 The MIT License (MIT)

 Copyright (c) 2015-2018 Douglas J. Bakkum

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


#define UTILS_BUFFER_LEN COMMANDER_REPORT_SIZE
#define VARINT_LEN 20
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))
#define MAX(a, b)  (((a) > (b)) ? (a) : (b))
#define strlens(s) (s == NULL ? 0 : strlen(s))
#define STREQ(a, b) (strcmp((a), (b))  == 0)


volatile void *utils_zero(volatile void *dst, size_t len);
void utils_clear_buffers(void);
uint8_t utils_is_hex(const char *str);
uint8_t utils_limit_alphanumeric_hyphen_underscore_period(const char *str);
uint8_t *utils_hex_to_uint8(const char *str);
char *utils_uint8_to_hex(const uint8_t *bin, size_t l);
void utils_reverse_hex(char *h, int len);
void utils_reverse_bin(uint8_t *b, int len);
void utils_uint64_to_varint(char *vi, int *l, uint64_t i);
int utils_varint_to_uint64(const char *vi, uint64_t *i);


#endif
