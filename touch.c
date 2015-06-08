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
#include <stdio.h>
#include "led.h"
#include "flags.h"
#include "touch.h"
#include "memory.h"
#include "systick.h"
#include "commander.h"


extern volatile uint16_t systick_current_time_ms;

volatile uint16_t status_flag			= 0u;
volatile uint16_t burst_flag			= 0u;
uint16_t qt_holdtime_ms				    = 1000u;
uint16_t qt_timeout_ms_min				= 1000u;


#ifndef TESTING
#include "mcu.h"
#include "touch_api.h"


void touch_init(void)
{
	qt_reset_sensing();
	qt_enable_key(TOUCH_CHANNEL, AKS_GROUP_1, 4u, HYST_6_25);
	qt_init_sensing();

	qt_config_data.qt_di = DEF_QT_DI;
	qt_config_data.qt_neg_drift_rate = DEF_QT_NEG_DRIFT_RATE;
	qt_config_data.qt_pos_drift_rate = DEF_QT_POS_DRIFT_RATE;
	qt_config_data.qt_max_on_duration = DEF_QT_MAX_ON_DURATION;
	qt_config_data.qt_drift_hold_time = DEF_QT_DRIFT_HOLD_TIME;
	qt_config_data.qt_recal_threshold = DEF_QT_RECAL_THRESHOLD;
	qt_config_data.qt_pos_recal_delay = DEF_QT_POS_RECAL_DELAY;

	qt_filter_callback = 0;
}
#endif


uint8_t touch_button_press(int long_touch)
{
	int pushed = NOT_TOUCHED;
	int status = ERROR;
	char message[128];
	int16_t touch_snks;
	int16_t touch_sns;
	uint16_t exit_time_ms;
	
	uint16_t qt_timeout_ms = memory_read_touch_timeout();
	uint16_t qt_sensor_thresh = memory_read_touch_thresh();
	
	led_on();
	
	// Make high priority so that we can timeout
	NVIC_SetPriority(SysTick_IRQn, 0);	

	systick_current_time_ms = 0;
    exit_time_ms = systick_current_time_ms + qt_timeout_ms;
	while (systick_current_time_ms < exit_time_ms || long_touch) {
		do {
			status_flag = qt_measure_sensors(systick_current_time_ms);
			burst_flag = status_flag & QTLIB_BURST_AGAIN;
		} while (burst_flag);
	
		touch_snks = qt_measure_data.channel_references[TOUCH_CHANNEL]; 
		touch_sns = qt_measure_data.channel_signals[TOUCH_CHANNEL];
		
        if ((touch_snks - touch_sns ) > qt_sensor_thresh) {
			// Touched
			led_off();
			exit_time_ms = systick_current_time_ms + qt_timeout_ms;
            while (systick_current_time_ms < exit_time_ms) {
                do {
                    status_flag = qt_measure_sensors(systick_current_time_ms);
                    burst_flag = status_flag & QTLIB_BURST_AGAIN;
                } while (burst_flag);
            
                touch_snks = qt_measure_data.channel_references[TOUCH_CHANNEL]; 
                touch_sns = qt_measure_data.channel_signals[TOUCH_CHANNEL];
			
                // If released before exit_time_ms for long_touch, answer is 'reject'
                if (long_touch && (touch_snks - touch_sns ) < (qt_sensor_thresh / 2)) {
                    pushed = ERROR;
					break;
				} else if (!long_touch) {
					pushed = TOUCHED;
					break;
                } else {
					pushed = TOUCHED;
				}
            }
			break;
		}
	}
		
	// Reset lower priority
	NVIC_SetPriority(SysTick_IRQn, 15);
	if (pushed == TOUCHED) {
		sprintf(message, "accept");
		status = SUCCESS;
		led_on();  delay_ms(300);
		led_off(); delay_ms(300);
		led_on();  delay_ms(300);
		led_off();
		
	} else if (pushed == ERROR) {
		sprintf(message, "Aborted by user.");
		status = ERROR;
		led_on();  delay_ms(100);
		led_off(); delay_ms(100);
		led_on();  delay_ms(100);
		led_off(); delay_ms(100);
		led_on();  delay_ms(100);
		led_off();
			
	} else {
		sprintf(message, "Touchbutton timed out. (%d/%d)", qt_measure_data.channel_signals[TOUCH_CHANNEL], 
													       qt_measure_data.channel_references[TOUCH_CHANNEL]);
		status = ERROR;
		led_off();
	} 
	
    commander_fill_report("touchbutton", message, status);
    return pushed;
}

void touch_button_parameters(uint16_t timeout, uint16_t threshold)
{	
	char message[32];
	uint16_t qt_timeout_ms = memory_read_touch_timeout();
	uint16_t qt_sensor_thresh = memory_read_touch_thresh();

	if (timeout > 0 && qt_timeout_ms != timeout) {
		if (timeout > qt_timeout_ms_min) {
			qt_timeout_ms = timeout;
		} else {
			qt_timeout_ms = qt_timeout_ms_min;			
		}
		memory_write_touch_timeout(qt_timeout_ms);
	}
	
    if (threshold > 0 && qt_sensor_thresh != threshold) {
		qt_sensor_thresh = threshold;
		memory_write_touch_thresh(qt_sensor_thresh);
	}
	
	sprintf(message,"%d", qt_timeout_ms / 1000);
	commander_fill_report("touch timeout", message, SUCCESS);

	sprintf(message,"%d", qt_sensor_thresh);
	commander_fill_report("touch threshold", message, SUCCESS);
}
