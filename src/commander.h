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


#ifndef _COMMANDER_H_
#define _COMMANDER_H_


#include <stdint.h>
#include "memory.h"


char *aes_cbc_b64_encrypt(const unsigned char *in, int inlen, int *out_b64len,
                          const uint8_t *key);
char *aes_cbc_b64_decrypt(const unsigned char *in, int inlen, int *decrypt_len,
                          const uint8_t *key);

void commander_clear_report(void);
const char *commander_read_report(void);
const char *commander_read_array(void);
void commander_fill_report(const char *attr, const char *val, int err);
int commander_fill_signature_array(const uint8_t *sig, uint8_t recid);
int commander_fill_json_array(const char **key, const char **value, int *type,
                              int cmd);
void commander_force_reset(void);
void commander_create_verifypass(void);
char *commander(const char *command);


#endif
