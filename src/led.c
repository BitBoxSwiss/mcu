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


#include "led.h"
#include "drivers/config/mcu.h"
#ifndef TESTING
#include <gpio.h>
#include <delay.h>
#include <ioport.h>
#else


#define LED_0_PIN               0
#define IOPORT_PIN_LEVEL_LOW    1
#define IOPORT_PIN_LEVEL_HIGH   0


static void ioport_set_pin_level(int led, int level)
{
    (void)led;
    (void)level;
}


static int ioport_get_pin_level(int led)
{
    (void)led;
    return 0;
}


#endif


void led_on(void)
{
    ioport_set_pin_level(LED_0_PIN, IOPORT_PIN_LEVEL_LOW);
}


void led_off(void)
{
    ioport_set_pin_level(LED_0_PIN, IOPORT_PIN_LEVEL_HIGH);

}


void led_toggle(void)
{
    ioport_set_pin_level(LED_0_PIN, !ioport_get_pin_level(LED_0_PIN));
}

/**
 * Blink the LED.
 * Do not expose this function via API (to prevent possible security problems during TFA pairing).
 */
void led_blink(void)
{
    led_on();
    delay_ms(300);
    led_off();
}


void led_abort(void)
{
    led_off();
    delay_ms(300);
    for (int i = 0; i < 6; i++) {
        led_on();
        delay_ms(100);
        led_off();
        delay_ms(100);
    }
}

void led_code(uint8_t code)
{
    uint8_t i;
    delay_ms(500);
    for (i = 0; i < code; i++) {
        led_toggle();
        delay_ms(300);
        led_toggle();
        delay_ms(300);
    }
    delay_ms(500);
}
