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
#include <stdio.h>
#include <string.h>
#include "drivers/config/conf_usb.h"
#include "drivers/config/mcu.h"
#include "sd.h"
#include "usb.h"
#include "ecc.h"
#include "led.h"
#include "touch.h"
#include "memory.h"
#include "random.h"
#include "systick.h"
#include "ataes132.h"
#include "commander.h"


uint32_t __stack_chk_guard = 0;

extern void __attribute__((noreturn)) __stack_chk_fail(void);
void __attribute__((noreturn)) __stack_chk_fail(void)
{
    while (1) {
        led_toggle();
        delay_ms(300);
    }
}


void SysTick_Handler(void)
{
    systick_update_time();
}


char usb_serial_number[USB_DEVICE_GET_SERIAL_NAME_LENGTH];

int main (void)
{
    wdt_disable(WDT);
    irq_initialize_vectors();
    cpu_irq_enable();
    sleepmgr_init();
    sysclk_init();
    board_init();
    ataes_init();
    __stack_chk_guard = random_uint32(0);
    flash_init(FLASH_ACCESS_MODE_128, 6);
    pmc_enable_periph_clk(ID_PIOA);
    delay_init(F_CPU);
    systick_init();
    touch_init();
    ecc_context_init();

    memset(usb_serial_number, 0, sizeof(usb_serial_number));
    snprintf(usb_serial_number, sizeof(usb_serial_number), "%s%s",
             USB_DEVICE_SERIAL_NAME_TYPE, DIGITAL_BITBOX_VERSION_SHORT);

    if (memory_read_erased()) {
        usb_serial_number[USB_DEVICE_GET_SERIAL_NAME_LENGTH - 2] = '-';
        usb_serial_number[USB_DEVICE_GET_SERIAL_NAME_LENGTH - 1] = '-';
    }

    usb_suspend_action();
    udc_start();

    led_on();
    delay_ms(300);
    led_off();

    memory_setup();

    while (1) {
        sleepmgr_enter_sleep();
    }
}
