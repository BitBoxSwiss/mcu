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
#include "usb.h"
#include "ecc.h"
#include "led.h"
#include "touch.h"
#include "memory.h"
#include "random.h"
#include "systick.h"
#include "commander.h"
#include "board_com.h"


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

int main (void)
{
    wdt_disable(WDT);
    irq_initialize_vectors();
    cpu_irq_enable();
    sysclk_init();
    board_com_init();
    __stack_chk_guard = random_uint32(0);
    pmc_enable_periph_clk(ID_PIOA);
    delay_init(F_CPU);
    systick_init();

    while (1) {
        led_on();
        delay_ms(1000);
        led_off();
        delay_ms(1000);
        led_on();
    }

}
