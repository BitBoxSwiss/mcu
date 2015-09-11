/*

 The MIT License (MIT)

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

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sham.h"
#include "commander.h"
#include "flags.h"


static char sd_filename[64] = {0};
static char sd_text[512] = {0};

void delay_ms(int delay)
{
    (void) delay;
}


uint8_t sd_write(const char *f, uint16_t f_len, const char *t, uint16_t t_len,
                 uint8_t replace)
{
    (void) replace;
    memset(sd_filename, 0, sizeof(sd_filename));
    memset(sd_text, 0, sizeof(sd_text));
    snprintf(sd_filename, sizeof(sd_filename), "%.*s", f_len, f);
    snprintf(sd_text, sizeof(sd_text), "%.*s", t_len, t);
    commander_fill_report("sd_write", FLAG_ERR_NO_MCU, STATUS_OK);
    return STATUS_OK;
}


char *sd_load(const char *f, uint16_t f_len)
{
    static char text[512];
    memcpy(text, sd_text, 512);
    commander_fill_report("sd_load", FLAG_ERR_NO_MCU, STATUS_OK);
    if (!strncmp(sd_filename, f, f_len)) {
        return text;
    }
    return NULL;
}


uint8_t sd_list(void)
{
    commander_fill_report("sd_list", FLAG_ERR_NO_MCU, STATUS_OK);
    if (sd_filename[0]) {
        commander_fill_report("backup", sd_filename, STATUS_OK);
    }
    return STATUS_OK;
}


uint8_t sd_erase(void)
{
    commander_fill_report("sd_erase", FLAG_ERR_NO_MCU, STATUS_OK);
    memset(sd_filename, 0, sizeof(sd_filename));
    memset(sd_text, 0, sizeof(sd_text));
    return STATUS_OK;
}


uint8_t touch_button_press(int long_touch)
{
    (void) long_touch;
    commander_fill_report("touchbutton", FLAG_ERR_NO_MCU, STATUS_OK);
    return STATUS_TOUCHED;
}


uint8_t flash_read_unique_id(uint32_t *serial, uint32_t len)
{
    memset(serial, 1, sizeof(uint32_t) * len);
    return 0; // success
}
