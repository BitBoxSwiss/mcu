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

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sham.h"
#include "flags.h"
#include "commander.h"


void delay_ms(int delay)
{
    (void) delay;
}


uint8_t touch_short_count = 0;

uint8_t touch_button_press(uint8_t touch_type)
{
    if (touch_type == DBB_TOUCH_REJECT_TIMEOUT) {
        // Simulate touch sequence for ecdh led blink coding
        if (!touch_short_count) {
            touch_short_count++;
            return DBB_ERR_TOUCH_TIMEOUT;
        } else {
            touch_short_count = 0;
            return DBB_ERR_TOUCH_ABORT;
        }
    }
    commander_fill_report(cmd_str(CMD_touchbutton), flag_msg(DBB_WARN_NO_MCU), DBB_OK);
    return DBB_TOUCHED;
}


uint8_t flash_read_unique_id(uint32_t *serial, uint32_t len)
{
    memset(serial, 1, sizeof(uint32_t) * len);
    return 0; // success
}
