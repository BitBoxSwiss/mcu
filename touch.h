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


#ifndef _TOUCH_H_
#define _TOUCH_H_

#include <stdint.h>

#ifndef NOT_EMBEDDED
#define TOUCH_CHANNEL					CHANNEL_9
#define QTOUCH_LIB_TYPE_MASK			0x01
#define QTOUCH_LIB_COMPILER_OFFSET		2
#define QTOUCH_LIB_COMPILER_MASK		0x01
#define QTOUCH_LIB_MAX_CHANNEL_OFFSET   3
#define QTOUCH_LIB_MAX_CHANNEL_MASK		0x7F
#define QTOUCH_LIB_KEY_ONLY_OFFSET		10
#define QTOUCH_LIB_KEY_ONLY_MASK		0x01
#define QTOUCH_LIB_ROTOR_NUM_OFFSET		11
#define QTOUCH_LIB_ROTOR_NUM_MASK		0x1F
#define GET_SENSOR_STATE(SENSOR_NUMBER) (qt_measure_data.qt_touch_status.sensor_states[(SENSOR_NUMBER/8)] & (1 << (SENSOR_NUMBER % 8)))
#endif


void touch_button_parameters(uint16_t timeout, uint16_t threshold, int status);
void touch_update_time(void);
void touch_init(void);
uint8_t touch_button_press(void);


#endif
