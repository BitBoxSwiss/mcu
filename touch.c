/*

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
#include "touch.h"
#include "memory.h"
#include "commander.h"


volatile uint8_t time_to_measure_touch	= 0u;	
volatile uint16_t current_time_ms_touch = 0u;	
uint16_t qt_measurement_period_msec		= 25u;	
uint16_t qt_timeout_ms_min				= 1000u;
uint16_t qt_timeout_ms					= 5000u;
uint16_t qt_sensor_thresh				= 100u;	
uint8_t qt_button_enable                = 1u;
volatile uint16_t status_flag			= 0u;
volatile uint16_t burst_flag			= 0u;

const char * qt_button_str[] = {"disable", "enable"};

#ifndef NOT_EMBEDDED
#include <asf.h>
#include "touch_api.h"

void touch_update_time(void)
{
	time_to_measure_touch = 1u;
	current_time_ms_touch += qt_measurement_period_msec; 
}


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

	// Configure timer ISR to fire regularly
	SysTick_Config((sysclk_get_cpu_hz() / 1000) * qt_measurement_period_msec);
	
	qt_filter_callback = 0;
	qt_timeout_ms = memory_touch_timeout_read();
	qt_sensor_thresh = memory_touch_thresh_read();	
    qt_button_enable = memory_touch_enable_read();
}
#endif

uint8_t touch_button_press(void)
{
	int pushed = 0;
	int status = ERROR;
	char message[128];
    if (!qt_button_enable) {
	    pushed = 1;
	    status = SUCCESS;
	    sprintf(message,"touch button disabled");
    } else {
#ifdef NOT_EMBEDDED
		pushed = 1;
		status = SUCCESS;
		sprintf(message, "touched (hard coded)");
#else 
		// Make high priority so that we can timeout
		NVIC_SetPriority(SysTick_IRQn, 0);
	
		int16_t touch_snks;
		int16_t touch_sns;
		uint16_t exit_time_ms = current_time_ms_touch + qt_timeout_ms;

		while (current_time_ms_touch < exit_time_ms) {
			do {
				//  One time measure touch sensors
				status_flag = qt_measure_sensors(current_time_ms_touch);
				burst_flag = status_flag & QTLIB_BURST_AGAIN;
			} while (burst_flag);
	
			touch_snks = qt_measure_data.channel_references[TOUCH_CHANNEL]; 
			touch_sns = qt_measure_data.channel_signals[TOUCH_CHANNEL];
		
			if ((touch_snks - touch_sns ) > qt_sensor_thresh) {
				delay_ms(300); 	led_toggle();
				delay_ms(300);	led_toggle();  
				pushed = 1;		
				break;	
			}
		}
		// Reset lower priority
		NVIC_SetPriority(SysTick_IRQn, 15);
		if (pushed) {
			sprintf(message,"touched (%d/%d)", qt_measure_data.channel_signals[TOUCH_CHANNEL], 
                                               qt_measure_data.channel_references[TOUCH_CHANNEL]);
			status = SUCCESS;
		} else {
			sprintf(message,"not touched (%d/%d)", qt_measure_data.channel_signals[TOUCH_CHANNEL], 
                                                   qt_measure_data.channel_references[TOUCH_CHANNEL]);
			status = ERROR;
		}
#endif
	}
    fill_report("touchbutton", message, status);
    return pushed;
}

void touch_button_parameters(uint16_t timeout, uint16_t threshold, int status)
{
	if (timeout > 0 && qt_timeout_ms != timeout) {
		if (timeout > qt_timeout_ms_min) {
			qt_timeout_ms = timeout;
		} else {
			qt_timeout_ms = qt_timeout_ms_min;			
		}
		memory_touch_timeout_write(qt_timeout_ms);
	}
	
    if (threshold > 0 && qt_sensor_thresh != threshold) {
		qt_sensor_thresh = threshold;
		memory_touch_thresh_write(qt_sensor_thresh);
	}

    if (status >= 0 && qt_button_enable != status) {
        qt_button_enable = status;
        memory_touch_enable_write(qt_button_enable);
    }

	char message[64];
	sprintf(message,"{\"timeout\":\"%d\",\"threshold\":\"%d\",\"button\":\"%s\"}", 
                    qt_timeout_ms, qt_sensor_thresh, qt_button_str[qt_button_enable]);
	fill_report("touchbutton", message, SUCCESS);
}


