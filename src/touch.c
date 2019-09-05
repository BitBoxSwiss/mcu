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


#include <stdio.h>
#include "led.h"
#include "flags.h"
#include "touch.h"
#include "hw_version.h"
#include "systick.h"
#include "commander.h"
#ifndef TESTING
#include "drivers/config/mcu.h"
#include "touch_api.h"
#endif


extern volatile uint16_t systick_current_time_ms;
volatile uint16_t status_flag = 0u;
volatile uint16_t burst_flag = 0u;


void touch_init(void)
{
#ifdef TESTING
    // pass
#else
    qt_reset_sensing();
    qt_enable_key(QTOUCH_TOUCH_CHANNEL, AKS_GROUP_1, 4u, HYST_6_25);
    qt_init_sensing();

    qt_config_data.qt_di = DEF_QT_DI;
    qt_config_data.qt_neg_drift_rate = DEF_QT_NEG_DRIFT_RATE;
    qt_config_data.qt_pos_drift_rate = DEF_QT_POS_DRIFT_RATE;
    qt_config_data.qt_max_on_duration = DEF_QT_MAX_ON_DURATION;
    qt_config_data.qt_drift_hold_time = DEF_QT_DRIFT_HOLD_TIME;
    qt_config_data.qt_recal_threshold = DEF_QT_RECAL_THRESHOLD;
    qt_config_data.qt_pos_recal_delay = DEF_QT_POS_RECAL_DELAY;

    qt_filter_callback = 0;
#endif
}


uint8_t touch_button_press(uint8_t touch_type)
{
#ifdef TESTING
    (void) touch_type;
    commander_fill_report(cmd_str(CMD_touchbutton), flag_msg(DBB_WARN_NO_MCU), DBB_OK);
    return DBB_TOUCHED;
#else
    int pushed = DBB_NOT_TOUCHED;
    int16_t touch_snks;
    int16_t touch_sns;
    uint16_t exit_time_ms;
    uint16_t qt_led_toggle_ms;
    uint16_t touch_thresh = QTOUCH_TOUCH_THRESH;
    if (report_hw_version() == HW_VERSION_V1_2) {
        touch_thresh = QTOUCH_TOUCH_THRESH_HW_V1_2;
    }


    if (touch_type >= TOUCH_REQUIRE_TOUCH) {
        return DBB_ERROR;
    }

    led_on();

    // Make higher priority so that we can timeout
    NVIC_SetPriority(SysTick_IRQn, 4);

    qt_led_toggle_ms = QTOUCH_TOUCH_BLINK_OFF;
    systick_current_time_ms = 0;
    while (systick_current_time_ms < QTOUCH_TOUCH_TIMEOUT ||
            touch_type == TOUCH_SHORT ||
            touch_type < TOUCH_REQUIRE_LONG_TOUCH) {

        if (systick_current_time_ms > QTOUCH_TOUCH_TIMEOUT_HARD) {
            break;
        }

        if (touch_type == TOUCH_U2F && systick_current_time_ms > QTOUCH_TOUCH_TIMEOUT_U2F) {
            break;
        }

        // Send an intermittent blink indicator for each touch type.
        if (touch_type < TOUCH_REQUIRE_LONG_TOUCH && systick_current_time_ms > qt_led_toggle_ms) {
            if (systick_current_time_ms > qt_led_toggle_ms + QTOUCH_TOUCH_BLINK_OFF) {
                qt_led_toggle_ms += QTOUCH_TOUCH_BLINK_ON + QTOUCH_TOUCH_BLINK_OFF;
                switch (touch_type) {
                    case TOUCH_LONG_SIGN:
                        led_sign();
                        break;
                    case TOUCH_LONG_BOOT:
                        led_boot_unlock();
                        break;
                    case TOUCH_LONG_PW:
                        led_password();
                        break;
                    case TOUCH_LONG_PAIR:
                        led_pair();
                        break;
                    default:
                        led_warn();
                        break;
                }
                led_on();
            }
        }

        do {
            status_flag = qt_measure_sensors(systick_current_time_ms);
            burst_flag = status_flag & QTLIB_BURST_AGAIN;
        } while (burst_flag);

        touch_snks = qt_measure_data.channel_references[QTOUCH_TOUCH_CHANNEL];
        touch_sns = qt_measure_data.channel_signals[QTOUCH_TOUCH_CHANNEL];

        if ((touch_snks - touch_sns ) > touch_thresh) {
            // Touched
            led_off();
            exit_time_ms = systick_current_time_ms + QTOUCH_TOUCH_TIMEOUT;
            while (systick_current_time_ms < exit_time_ms) {
                do {
                    status_flag = qt_measure_sensors(systick_current_time_ms);
                    burst_flag = status_flag & QTLIB_BURST_AGAIN;
                } while (burst_flag);

                touch_snks = qt_measure_data.channel_references[QTOUCH_TOUCH_CHANNEL];
                touch_sns = qt_measure_data.channel_signals[QTOUCH_TOUCH_CHANNEL];

                if ((touch_snks - touch_sns) < (touch_thresh / 2)) {
                    // If released before exit_time_ms for:
                    //     - DBB_TOUCH_LONG_BLINK, answer is 'reject'
                    //     - DBB_TOUCH_LONG, answer is 'reject'
                    //     - TOUCH_SHORT, answer is 'accept'
                    if (touch_type  < TOUCH_REQUIRE_LONG_TOUCH) {
                        pushed = DBB_TOUCHED_ABORT;
                        break;
                    } else if (touch_type == TOUCH_SHORT) {
                        pushed = DBB_TOUCHED;
                        break;
                    }
                } else if (touch_type < TOUCH_REQUIRE_LONG_TOUCH) {
                    pushed = DBB_TOUCHED;
                } else if (touch_type == TOUCH_SHORT) {
                    pushed = DBB_TOUCHED_ABORT;
                } else if (touch_type == TOUCH_TIMEOUT || touch_type == TOUCH_U2F) {
                    // If touched before exit_time_ms for:
                    //     - TOUCH_TIMEOUT, answer is 'accept'
                    pushed = DBB_TOUCHED;
                    break;
                }
            }
            break;
        }
    }

    // Reset lower priority
    NVIC_SetPriority(SysTick_IRQn, 15);

    if (pushed == DBB_TOUCHED) {
        if (touch_type < TOUCH_REQUIRE_LONG_TOUCH) {
            led_success();
        }
        led_off();
        return DBB_TOUCHED;
    } else if (pushed == DBB_TOUCHED_ABORT) {
        led_abort();
        return DBB_ERR_TOUCH_ABORT;
    } else {
        led_off();
        return DBB_ERR_TOUCH_TIMEOUT;
    }
#endif
}
