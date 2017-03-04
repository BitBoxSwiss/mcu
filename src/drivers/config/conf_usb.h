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


#ifndef _CONF_USB_H_
#define _CONF_USB_H_


#include "compiler.h"
#include "usb_protocol.h"
#include "usb_protocol_hid.h"
#include "../../version.h"
#include "../../usb.h"


#define  USB_DEVICE_VENDOR_ID             0x03EB
#define  USB_DEVICE_PRODUCT_ID            0x2402
#define  USB_DEVICE_MAJOR_VERSION         DIGITAL_BITBOX_VERSION_MAJOR
#define  USB_DEVICE_MINOR_VERSION         DIGITAL_BITBOX_VERSION_MINOR
#define  USB_DEVICE_POWER                 100// Consumption (mA)
#define  USB_DEVICE_ATTR                  (USB_CONFIG_ATTR_BUS_POWERED)
#define  USB_DEVICE_MANUFACTURE_NAME      "www.shiftdevices.com"
#ifdef BOOTLOADER 
#define  USB_DEVICE_PRODUCT_NAME          "bootloader"
#define  USB_DEVICE_SERIAL_NAME_TYPE      "dbb.bl:"
#define  USB_DEVICE_SERIAL_NAME           USB_DEVICE_SERIAL_NAME_TYPE DIGITAL_BITBOX_VERSION_SHORT
#else
#define  USB_DEVICE_PRODUCT_NAME          "firmware"
#define  USB_DEVICE_SERIAL_NAME_TYPE      "dbb.fw:"
#define  USB_DEVICE_SERIAL_NAME
#define  USB_DEVICE_GET_SERIAL_NAME_POINTER usb_serial_number
#define  USB_DEVICE_GET_SERIAL_NAME_LENGTH 15
extern char usb_serial_number[];
#endif


#define  UDC_VBUS_EVENT(b_vbus_high)
#define  UDC_SOF_EVENT()                  usb_sof_action()
#define  UDC_SUSPEND_EVENT()              usb_suspend_action()
#define  UDC_RESUME_EVENT()               usb_resume_action()
#define  UDC_REMOTEWAKEUP_ENABLE()        usb_remotewakeup_enable()
#define  UDC_REMOTEWAKEUP_DISABLE()       usb_remotewakeup_disable()
 

#ifdef BOOTLOADER 
#define  UDI_HID_REPORT_IN_SIZE      256
#define  UDI_HID_REPORT_OUT_SIZE     4098
#else
#define  UDI_HID_REPORT_IN_SIZE      USB_REPORT_SIZE
#define  UDI_HID_REPORT_OUT_SIZE     USB_REPORT_SIZE
#endif
#define  UDI_HID_REPORT_FEATURE_SIZE 8
#define  UDI_HID_EP_SIZE             64


#define  UDI_HWW_IFACE_NUMBER         0
#define  UDI_HWW_EP_IN               (1 | USB_EP_DIR_IN)
#define  UDI_HWW_EP_OUT              (2 | USB_EP_DIR_OUT)
#define  UDI_HWW_ENABLE_EXT()        usb_hww_enable()
#define  UDI_HWW_DISABLE_EXT()       usb_hww_disable()
#define  UDI_HWW_REPORT_OUT(ptr)     usb_hww_report(ptr)


#define  UDI_U2F_IFACE_NUMBER        1
#define  UDI_U2F_EP_IN               (3 | USB_EP_DIR_IN)
#define  UDI_U2F_EP_OUT              (4 | USB_EP_DIR_OUT)
#define  UDI_U2F_ENABLE_EXT()        usb_u2f_enable()
#define  UDI_U2F_DISABLE_EXT()       usb_u2f_disable()
#define  UDI_U2F_REPORT_OUT(ptr)     usb_u2f_report(ptr)
#define  UDI_U2F_REPORT_SENT()       usb_u2f_report_sent()


#define  UDI_HID_REPORT_SENT()       usb_report_sent()
#define  UDI_HID_SET_FEATURE(report) usb_set_feature(report)


// Interface descriptor structure for HID generic
typedef struct {
	usb_iface_desc_t iface;
	usb_hid_descriptor_t hid;
	usb_ep_desc_t ep_in;
	usb_ep_desc_t ep_out;
} udi_hid_generic_desc_t;


#ifdef BOOTLOADER 
#define  USB_DEVICE_EP_CTRL_SIZE       64
#define  USB_DEVICE_NB_INTERFACE       1
#define  USB_DEVICE_MAX_EP             2
#define  UDI_COMPOSITE_DESC_T           udi_hid_generic_desc_t hid_hww
#define  UDI_COMPOSITE_DESC             .hid_hww = UDI_HWW_DESC
#define  UDI_COMPOSITE_API              &udi_api_hww
#else
#define  USB_DEVICE_EP_CTRL_SIZE       64
#define  USB_DEVICE_NB_INTERFACE       2
#define  USB_DEVICE_MAX_EP             4
#define  UDI_COMPOSITE_DESC_T           udi_hid_generic_desc_t hid_hww; udi_hid_generic_desc_t hid_u2f
#define  UDI_COMPOSITE_DESC             .hid_hww = UDI_HWW_DESC, .hid_u2f = UDI_U2F_DESC
#define  UDI_COMPOSITE_API              &udi_api_hww, &udi_api_u2f
#endif


// Keep these includes at the end of the file
#include "udi_hid_generic.h"
#include "udi_hid_u2f.h"


#endif
