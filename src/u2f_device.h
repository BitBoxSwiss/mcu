/*

 The MIT License (MIT)

 Copyright (c) 2016-2017 Douglas J. Bakkum, Shift Devices AG

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


#ifndef __U2F_DEVICE_H__
#define __U2F_DEVICE_H__


#include <stdint.h>
#include <stdbool.h>
#include "usb.h"
#include "u2f/u2f.h"


#define U2F_HIJACK_ORIGIN_TOTAL 4


extern const uint8_t U2F_HIJACK_CODE[U2F_HIJACK_ORIGIN_TOTAL][U2F_APPID_SIZE];

typedef enum HIJACK_STATE {
    // Do not change the order!
    // Order affects third party integrations that make use of the hijack mode
    HIJACK_STATE_RESPONSE_READY,
    HIJACK_STATE_PROCESSING_COMMAND,
    HIJACK_STATE_INCOMPLETE_COMMAND,
    HIJACK_STATE_IDLE,
} HIJACK_STATE;


void u2f_queue_message(const uint8_t *data, const uint32_t len);
void u2f_queue_error_hid(uint32_t fcid, uint8_t err);
void u2f_device_run(const USB_FRAME *f);
void u2f_device_timeout(void);


#endif
