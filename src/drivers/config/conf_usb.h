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


#ifndef _CONF_USB_H_
#define _CONF_USB_H_


#include "compiler.h"
#include "../../version.h"


// Device definition 
#define  USB_DEVICE_VENDOR_ID             0x03EB
#define  USB_DEVICE_PRODUCT_ID            0x2402
#define  USB_DEVICE_MAJOR_VERSION         1
#define  USB_DEVICE_MINOR_VERSION         0
#define  USB_DEVICE_POWER                 100// Consumption (mA)
#define  USB_DEVICE_ATTR                  \
  (USB_CONFIG_ATTR_BUS_POWERED)
//	(USB_CONFIG_ATTR_REMOTE_WAKEUP|USB_CONFIG_ATTR_BUS_POWERED)
//	(USB_CONFIG_ATTR_SELF_POWERED)
//	(USB_CONFIG_ATTR_REMOTE_WAKEUP|USB_CONFIG_ATTR_SELF_POWERED)
//	(USB_CONFIG_ATTR_REMOTE_WAKEUP|USB_CONFIG_ATTR_BUS_POWERED)

// USB Device string definitions (Optional)
#ifdef BOOTLOADER 
#define  USB_DEVICE_MANUFACTURE_NAME      "Digital Bitbox Bootloader"
#define  USB_DEVICE_SERIAL_NAME_TYPE      "dbb.bl:"
#else
#define  USB_DEVICE_MANUFACTURE_NAME      "Digital Bitbox"
#define  USB_DEVICE_SERIAL_NAME_TYPE      "dbb.fw:"
#endif
#define  USB_DEVICE_PRODUCT_NAME          "www.digitalbitbox.com"
#define  USB_DEVICE_SERIAL_NAME           USB_DEVICE_SERIAL_NAME_TYPE DIGITAL_BITBOX_VERSION_SHORT


#define  UDC_VBUS_EVENT(b_vbus_high)
#define  UDC_SOF_EVENT()                  usb_sof_action()
#define  UDC_SUSPEND_EVENT()              usb_suspend_action()
#define  UDC_RESUME_EVENT()               usb_resume_action()
#define  UDC_REMOTEWAKEUP_ENABLE()        usb_remotewakeup_enable()
#define  UDC_REMOTEWAKEUP_DISABLE()       usb_remotewakeup_disable()
 
#define  UDI_HID_GENERIC_ENABLE_EXT()        usb_enable()
#define  UDI_HID_GENERIC_DISABLE_EXT()       usb_disable()
#define  UDI_HID_GENERIC_REPORT_OUT(ptr)     usb_report(ptr)
#define  UDI_HID_GENERIC_SET_FEATURE(report) usb_hid_set_feature(report)


#ifdef BOOTLOADER 
#define  UDI_HID_REPORT_IN_SIZE             256
#define  UDI_HID_REPORT_OUT_SIZE            4098
#define  UDI_HID_REPORT_FEATURE_SIZE        8
#else
#define  UDI_HID_REPORT_IN_SIZE             2048
#define  UDI_HID_REPORT_OUT_SIZE            2048
#endif
#define  UDI_HID_REPORT_FEATURE_SIZE        8
#define  UDI_HID_GENERIC_EP_SIZE            64


// Keep these includes at the end of the file
#include "udi_hid_generic_conf.h"
#include "../../usb.h"


#endif // _CONF_USB_H_
