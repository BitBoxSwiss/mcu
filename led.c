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
#include "led.h"
#include "memory.h"
#include "commander.h"
#ifndef NOT_EMBEDDED
#include <gpio.h>
#include <delay.h>
#include <ioport.h>
#else
void ioport_set_pin_level(int led, int level){ (void)led; (void)level; }
int ioport_get_pin_level(int led){ (void)led; return 0; }
#define LED_0_PIN               0
#define IOPORT_PIN_LEVEL_LOW    1
#define IOPORT_PIN_LEVEL_HIGH   0
#endif


LED_STATE LED_State = LED_ENABLE; 


void led_init( void )
{
	LED_State = memory_led_read();	
}

void led_off( void )
{
	if(LED_State==LED_ENABLE || LED_State==LED_OFF)
	{
		ioport_set_pin_level(LED_0_PIN, IOPORT_PIN_LEVEL_HIGH);
	}
}

void led_on( void )
{
	if(LED_State==LED_ENABLE || LED_State==LED_ON)
	{
		ioport_set_pin_level(LED_0_PIN, IOPORT_PIN_LEVEL_LOW);
	}
}

void led_toggle( void )
{
	if(LED_State!=LED_DISABLE)
	{
		ioport_set_pin_level(LED_0_PIN,!ioport_get_pin_level(LED_0_PIN));
	}
}


void led_off_flash( void )
{
	if(LED_State!=LED_DISABLE)
	{
		ioport_set_pin_level(LED_0_PIN, IOPORT_PIN_LEVEL_HIGH);
		delay_ms(300);
		ioport_set_pin_level(LED_0_PIN, IOPORT_PIN_LEVEL_LOW);
		delay_ms(300);
		ioport_set_pin_level(LED_0_PIN, IOPORT_PIN_LEVEL_HIGH);
	}
}


static int get_led_state(const char * state)
{
	if( strcmp(state,"disable") == 0 )
	{
		return LED_DISABLE;
	}
	else if( strcmp(state,"enable") == 0 )
	{
		return LED_ENABLE;
	}
	else if( strcmp(state,"on") == 0 )
	{
		return LED_ON;
	}
	else if( strcmp(state,"off") == 0 )
	{
		return LED_OFF;
	}
	else
	{	
		return -1; // Invalid state
	}
}

const char * led_state( const char * state )
{
    if( !state )
    {
        return "Invalid state. [NULL]"; 
    }

    int s = get_led_state(state); 

    if( s < 0 )
    {
        return "Invalid state.";
    }

	if( s != (int)LED_State )
	{
		memory_led_write(s); 
	}
	
	switch( s )
	{
		case LED_DISABLE:
			LED_State = LED_DISABLE;
			ioport_set_pin_level(LED_0_PIN, IOPORT_PIN_LEVEL_HIGH);
			return "disable";
			//break;
		
		case LED_ENABLE:
			LED_State = LED_ENABLE;
			led_off_flash();
			return "enable";
		
		case LED_ON:
			LED_State = LED_ON;
			ioport_set_pin_level(LED_0_PIN, IOPORT_PIN_LEVEL_LOW);
			return "on";
		
		case LED_OFF:
			LED_State = LED_OFF;
			ioport_set_pin_level(LED_0_PIN, IOPORT_PIN_LEVEL_HIGH);
			return "off";	
	}	
	return "Invalid state. [ret]";
}


