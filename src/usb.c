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


#include <string.h>

#ifndef TESTING
#include "conf_usb.h"
#include "mcu.h"
#ifdef BOOTLOADER
#include "bootloader.h"
#endif
#endif
#include "utils.h"
#include "usb.h"
#include "u2f_device.h"


#define USB_QUEUE_NUM_PACKETS 128


static uint8_t usb_reply_queue_packets[USB_QUEUE_NUM_PACKETS][USB_REPORT_SIZE];
static uint32_t usb_reply_queue_index_start = 0;
static uint32_t usb_reply_queue_index_end = 0;


void usb_report(const unsigned char *command)
{
#ifdef BOOTLOADER
    bootloader_command((const char *)command);
#else
    u2f_device_run((const USB_FRAME *)command);
#endif
}


void usb_report_sent(void)
{
    usb_reply_queue_send();
}


void usb_reply(uint8_t *report)
{
    if (report) {
#ifndef TESTING
        if (udi_hid_generic_send_report_in(report)) {
            return;
        }
#endif
    }
}


uint8_t *usb_reply_queue_read(void)
{
    uint32_t p = usb_reply_queue_index_start;
    if (p == usb_reply_queue_index_end) {
        return NULL;    // No data
    }
    usb_reply_queue_index_start = (p + 1) % USB_QUEUE_NUM_PACKETS;
    return usb_reply_queue_packets[p];
}


void usb_reply_queue_clear(void)
{
    usb_reply_queue_index_start = usb_reply_queue_index_end;
}


void usb_reply_queue_add(const USB_FRAME *frame)
{
    uint32_t next = (usb_reply_queue_index_end + 1) % USB_QUEUE_NUM_PACKETS;
    if (usb_reply_queue_index_start == next) {
        return; // Buffer full
    }
    memcpy(usb_reply_queue_packets[usb_reply_queue_index_end], frame, USB_REPORT_SIZE);
    usb_reply_queue_index_end = next;
}


void usb_reply_queue_load_msg(const uint8_t cmd, const uint8_t *data, const uint32_t len,
                              const uint32_t cid)
{
    USB_FRAME f;
    uint32_t cnt = 0;
    uint32_t l = len;
    uint32_t psz;
    uint8_t seq = 0;

    memset(&f, 0, sizeof(f));
    f.cid = cid;
    f.init.cmd = cmd;
    f.init.bcnth = len >> 8;
    f.init.bcntl = len & 0xff;

    // Init packet
    psz = MIN(sizeof(f.init.data), l);
    memcpy(f.init.data, data, psz);
    usb_reply_queue_add(&f);
    l -= psz;
    cnt += psz;

    // Cont packet(s)
    for (; l > 0; l -= psz, cnt += psz) {
        memset(&f.cont.data, 0, sizeof(f.cont.data));
        f.cont.seq = seq++;
        psz = MIN(sizeof(f.cont.data), l);
        memcpy(f.cont.data, data + cnt, psz);
        usb_reply_queue_add(&f);
    }
}


void usb_reply_queue_send(void)
{
#ifndef TESTING
    static uint8_t *data;
    data = usb_reply_queue_read();
    if (data) {
        usb_reply(data);
    }
#endif
}


#ifndef TESTING
static bool usb_b_enable = false;

// Periodically called every 1(?) msec
// Can run timed locked processes here
void usb_process(uint16_t framenumber)
{
    static uint8_t cpt_sof = 0;

    cpt_sof++;
    if (cpt_sof < 40) {
        return;
    }
    cpt_sof = 0;

    u2f_device_timeout();

    (void)framenumber;
}


void usb_suspend_action(void) {}


void usb_resume_action(void) {}


void usb_sof_action(void)
{
    if (!usb_b_enable) {
        return;
    }
    usb_process(udd_get_frame_number());
}


void usb_remotewakeup_enable(void) {}


void usb_remotewakeup_disable(void) {}


bool usb_enable(void)
{
    usb_b_enable = true;
    return true;
}


void usb_disable(void)
{
    usb_b_enable = false;
}


void usb_hid_set_feature(uint8_t *report)
{
    if (report[0] == 0xAA && report[1] == 0x55
            && report[2] == 0xAA && report[3] == 0x55) {
        // Disconnect USB Device
        udc_stop();
        usb_suspend_action();
    }
}
#endif

