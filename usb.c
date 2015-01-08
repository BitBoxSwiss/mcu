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
#include <asf.h>
#include "conf_usb.h"
#include "commander.h"
#include "usb.h"

bool usb_b_enable = false;


void usb_report(const unsigned char *command)
{
	udi_hid_generic_send_report_in((uint8_t*)commander((const char *)command));
}


void usb_process(uint16_t framenumber)
{

	static uint8_t cpt_sof = 0;

	// Scan process running each 40ms
	cpt_sof++;
	if (cpt_sof < 40) {
		return;
	}
	cpt_sof = 0;

	if ( false ) { // can run timed locked processess here
        //
        // ...
        //
    }
}

void usb_suspend_action(void)
{
}

void usb_resume_action(void)
{
}

void usb_sof_action(void)
{
	if (!usb_b_enable)
		return;
	usb_process(udd_get_frame_number());
}

void usb_remotewakeup_enable(void)
{
}

void usb_remotewakeup_disable(void)
{
}

bool usb_enable(void)
{
	usb_b_enable = true;
	return true;
}

void usb_disable(void)
{
	usb_b_enable = false;
}


void usb_hid_set_feature(uint8_t* report)
{
	if (report[0] == 0xAA && report[1] == 0x55
			&& report[2] == 0xAA && report[3] == 0x55) {
		// Disconnect USB Device
		udc_stop();
		usb_suspend_action();
	}
}

