/*

 The MIT License (MIT)

 Copyright (c) 2015-2019 Douglas J. Bakkum, Shift Cryptosecurity

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
#include "flags.h"
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

/**
 * led_on() and led_off() should only be used internally by other led commands,
 * except in touch.c to allow touch readings to get registered while the led is on.
 */
void led_on(void)
{
    ioport_set_pin_level(LED_0_PIN, IOPORT_PIN_LEVEL_LOW);
}

void led_off(void)
{
    ioport_set_pin_level(LED_0_PIN, IOPORT_PIN_LEVEL_HIGH);
}

static void _short_blink(void)
{
    led_on();
    delay_ms(100);
    led_off();
    delay_ms(100);
}

static void _long_blink(void)
{
    led_on();
    delay_ms(300);
    led_off();
    delay_ms(300);
}

void led_toggle(void)
{
    ioport_set_pin_level(LED_0_PIN, !ioport_get_pin_level(LED_0_PIN));
}

/**
 * When a LONG_TOUCH is aborted.
 */
void led_abort(void)
{
    led_off();
    delay_ms(300);
    for (int i = 0; i < 8; i++) {
        _short_blink();
    }
}

/**
 * Long blink <code> times for 2FA mobile pairing
 */
void led_2FA_pairing_code(uint8_t code)
{
    if (code > LED_MAX_CODE_BLINKS) {
        return;
    }

    uint8_t i;
    delay_ms(500);
    for (i = 0; i < code; i++) {
        // Use explicit blink timing for led_code() to keep it independent,
        // for example of led_long(), which is used elsewhere.
        led_toggle();
        delay_ms(300);
        led_toggle();
        delay_ms(300);
    }
    delay_ms(500);
}

/**
 * Indicates one of:
 *   firmware startup
 *   long touch 'accept'
 *   commander_process_led()
 *   u2f_device_wink()
 *   bootloader_blink()
 */
void led_success(void)
{
    _short_blink();
    _long_blink();
}

/**
 * Alias of led_success for wink / blink commands.
 */
void led_wink(void)
{
    led_success();
}


/**
 * Indicate request to unlock the bootloader.
 */
void led_boot_unlock(void)
{
    // Pass
}

/**
 * Indicate request to sign. Do NOT use for other commands.
 */
void led_sign(void)
{
    _short_blink();
}

/**
 * Indicate request to set device password or access hidden wallet.
 */
void led_password(void)
{
    _short_blink();
    _short_blink();
}

/**
 * Indicate the request is potentially dangerous.
 * Applies to the lock device, erase backup, and reset/re-seed device commands.
 */
void led_warn(void)
{
    _short_blink();
    _short_blink();
    _short_blink();
}

/**
 * Indicate a request to start ECDH pairing. Do NOT use for other commands.
 */
void led_pair(void)
{
    _short_blink();
    _short_blink();
    _short_blink();
    _short_blink();
}
