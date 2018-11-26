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


#ifndef _CIPHER_H_
#define _CIPHER_H_


#include <stdint.h>


char *cipher_aes_b64_hmac_encrypt(const unsigned char *in, int inlen,
                                  int *out_b64len, const uint8_t *secret);

uint8_t *cipher_aes_hmac_encrypt(const unsigned char *in, int inlen,
                                 int *out_b64len, const uint8_t *secret);

char *cipher_aes_b64_encrypt(const unsigned char *in, int inlen,
                             int *out_b64len, const uint8_t *key);

char *cipher_aes_b64_hmac_decrypt(const unsigned char *in, int inlen, int *out_msg_len,
                                  const uint8_t *secret);

char *cipher_aes_b64_decrypt(const unsigned char *in, int inlen,
                             int *outlen, const uint8_t *key);

char *cipher_aes_hmac_decrypt(const uint8_t *in, int inlen,
                              int *outlen, const uint8_t *key);


#endif
