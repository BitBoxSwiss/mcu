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


#include <string.h>

#include "mcu.h"
#include "led.h"
#include "usb.h"
#include "flags.h"
#include "touch.h"
#include "systick.h"
#include "bootloader.h"
#include "sam4s4a.h"
#include "core_cm4.h"


void SysTick_Handler(void)
{
    systick_update_time();
}


void _binExec (void *l_code_addr);
void _binExec (void *l_code_addr)
{
    __asm__ (
        "mov   r1, r0        \n"
        "ldr   r0, [r1, #4]  \n"
        "ldr   sp, [r1]      \n"
        "blx   r0"
    );
    (void)l_code_addr;
}


static int binary_exec(void *vStart)
{
    int i;

    // Should be at least 32 words aligned
    if ((uint32_t)vStart & 0x7F) {
        return 1;
    }

    __disable_irq();
    for (i = 0; i < 8; i ++) {
        NVIC->ICER[i] = 0xFFFFFFFF;
    }
    for (i = 0; i < 8; i ++) {
        NVIC->ICPR[i] = 0xFFFFFFFF;
    }
    __DSB();
    __ISB();
    SCB->VTOR = ((uint32_t)vStart & SCB_VTOR_TBLOFF_Msk);
    __DSB();
    __ISB();
    __enable_irq();
    _binExec(vStart);

    return 0;
}


int main(void)
{
    void *app_start_addr = (void *)FLASH_APP_START;

    wdt_disable(WDT);
    irq_initialize_vectors();
    cpu_irq_enable();
    sysclk_init();
    board_init();
    flash_init(FLASH_ACCESS_MODE_128, 6);
    flash_enable_security_bit();
    pmc_enable_periph_clk(ID_PIOA);
    delay_init(F_CPU);
    systick_init();
    touch_init();

    if (bootloader_firmware_verified()) {
        if (!bootloader_unlocked()) {
            binary_exec(app_start_addr);
        } else if (touch_button_press(DBB_TOUCH_LONG) != DBB_TOUCHED) {
            binary_exec(app_start_addr);
        }
    } else {
        for (int i = 0; i < 9; i++) {
            led_toggle();
            delay_ms(100);
            led_toggle();
            delay_ms(150);
        }
        led_off();
    }

    // App not entered. Start USB API for bootloader
    usb_suspend_action();
    udc_start();

    for (int i = 0; i < 6; i++) {
        led_toggle();
        delay_ms(100);
    }
    led_off();

    while (true) { }

    return 0;
}

