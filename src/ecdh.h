/*

 The MIT License (MIT)

 Copyright (c) 2015-2018 Douglas J. Bakkum, Stephanie Stroka, Shift Cryptosecurity

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

#ifndef _ECDH_H_
#define _ECDH_H_

#include <stdint.h>

#include "yajl/src/api/yajl_tree.h"


#define CHALLENGE_MIN_BLINK_SETS 12// Minimum sets of blinks required before the shared secret is saved to eeprom
#define SIZE_ECDH_SHARED_SECRET SHA256_DIGEST_LENGTH


#ifdef TESTING
uint8_t *test_shared_secret_report(void);
void test_shared_secret_write(const uint8_t *data);
#endif
void ecdh_dispatch_command(yajl_val json_node);


#endif

