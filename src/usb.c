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
#endif
#include "bootloader.h"
#include "utils.h"
#include "usb.h"
#include "u2f_device.h"
#include "u2f/u2f_hid.h"


#define USB_QUEUE_NUM_PACKETS 128


static bool usb_hww_enabled = false;
static bool usb_u2f_enabled = false;
static bool usb_dbg_enabled = false;
static uint8_t usb_hww_interface_occupied = 0;
static uint8_t usb_reply_queue_packets[USB_QUEUE_NUM_PACKETS][USB_REPORT_SIZE];
static uint32_t usb_reply_queue_index_start = 0;
static uint32_t usb_reply_queue_index_end = 0;


void usb_hww_report(const unsigned char *command)
{
    usb_hww_interface_occupied = 1;
#ifdef BOOTLOADER
    bootloader_command((const char *)command);
#else
    usb_reply_queue_clear();// Give HWW priority
    u2f_device_run((const USB_FRAME *)command);
#endif
}


void usb_u2f_report(const unsigned char *command)
{
    const USB_FRAME *c = (const USB_FRAME *)command;
    if (usb_hww_interface_occupied) {
        // Give preference to HWW commands
        // Let U2F client timeout
        return;
    }
    if (c->type >= U2FHID_VENDOR_FIRST) {
        // Disable vendor defined commands in u2f interface
        u2f_send_err_hid(c->cid, U2FHID_ERR_INVALID_CMD);
        usb_reply_queue_send();
        return;
    }
    u2f_device_run(c);
}


void usb_report_sent(void)
{
    usb_reply_queue_send();
}


void usb_reply(uint8_t *report)
{
    if (report) {
#ifndef TESTING
        if (usb_hww_interface_occupied) {
            udi_hww_send_report_in(report);
        }
#ifndef BOOTLOADER
        else {
            udi_u2f_send_report_in(report);
        }
#endif
#endif
    }
}


void usb_reply_dbg(const char *msg, size_t len)
{
    if (msg && len) {
#if defined(ENABLE_DEBUG_IFACE)
        // TODO - send multiple reports if msg length > report size
        static char report[USB_REPORT_SIZE];
        memset(report, 0, USB_REPORT_SIZE);
        memcpy(report, msg, len < USB_REPORT_SIZE ? len : USB_REPORT_SIZE);
        udi_dbg_send_report_in(report);
#endif
    }
}


uint8_t *usb_reply_queue_read(void)
{
    uint32_t p = usb_reply_queue_index_start;
    if (p == usb_reply_queue_index_end) {
        // queue is empty
        usb_hww_interface_occupied = 0;
        return NULL;
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
    usb_reply(data);
#endif
}


void usb_set_feature(uint8_t *report)
{
    (void) report;
}


void usb_suspend_action(void) {}


void usb_resume_action(void) {}


void usb_remotewakeup_enable(void) {}


void usb_remotewakeup_disable(void) {}


bool usb_u2f_enable(void)
{
    usb_u2f_enabled = true;
    return true;
}


void usb_u2f_disable(void)
{
    usb_u2f_enabled = false;
}


bool usb_hww_enable(void)
{
    usb_hww_enabled = true;
    return true;
}


void usb_hww_disable(void)
{
    usb_hww_enabled = false;
}


bool usb_dbg_enable(void)
{
    usb_dbg_enabled = true;
    return true;
}


void usb_dbg_disable(void)
{
    usb_dbg_enabled = false;
}


// Periodically called every 1(?) msec
// Can run timed locked processes here
// Use for u2f timeout function
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


void usb_sof_action(void)
{
#if !defined(BOOTLOADER) && !defined(TESTING)
    if (!usb_u2f_enabled) {
        return;
    }
    usb_process(udd_get_frame_number());
#endif
}
