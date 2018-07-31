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

#include <stdint.h>

#include "sha2.h"
#include "utils.h"
#include "sharedsecret.h"

void sharedsecret_derive_keys(const uint8_t *shared_secret, uint8_t *encryption_key,
                              uint8_t *authentication_key)
{
    uint8_t encryption_and_authentication_key[SHA512_DIGEST_LENGTH];
    sha512_Raw(shared_secret, SHA256_DIGEST_LENGTH, encryption_and_authentication_key);

    int KEY_SIZE = SHA512_DIGEST_LENGTH / 2;

    memcpy(encryption_key, encryption_and_authentication_key, KEY_SIZE);
    memcpy(authentication_key, encryption_and_authentication_key + KEY_SIZE, KEY_SIZE);

    utils_zero(encryption_and_authentication_key, SHA512_DIGEST_LENGTH);
}


