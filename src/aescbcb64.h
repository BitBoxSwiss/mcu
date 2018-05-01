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

#ifndef _AESCBCB64_H_
#define _AESCBCB64_H_


char *aescbcb64_hmac_encrypt(const unsigned char *in, int inlen,
                             int *out_b64len, const uint8_t *shared_secret);

char *aescbcb64_init_and_decrypt(uint8_t *ub64, int ub64len, int *decrypt_len,
                                 const uint8_t *key);

char *aescbcb64_encrypt(const unsigned char *in, int inlen,
                        int *out_b64len, const uint8_t *key);

char *aescbcb64_decrypt(const unsigned char *in, int inlen,
                        int *decrypt_len, const uint8_t *key);

#endif
