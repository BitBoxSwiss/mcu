/**
 * \file
 *
 * \brief USB Device Human Interface Device (HID) generic interface.
 *
 * Copyright (c) 2009-2014 Atmel Corporation. All rights reserved.
 *
 * \asf_license_start
 *
 * \page License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Atmel may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel microcontroller product.
 *
 * THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * \asf_license_stop
 *
 */


#include "conf_usb.h"
#include "usb_protocol.h"
#include "udd.h"
#include "udc.h"
#include "udi_hid.h"
#include "udi_hid_hww.h"
#include <string.h>


bool udi_hww_enable(void);
void udi_hww_disable(void);
bool udi_hww_setup(void);
uint8_t udi_hww_getsetting(void);

// Global structure which contains standard UDI interface for UDC
UDC_DESC_STORAGE udi_api_t udi_api_hww = {
	.enable = (bool(*)(void))udi_hww_enable,
	.disable = (void (*)(void))udi_hww_disable,
	.setup = (bool(*)(void))udi_hww_setup,
	.getsetting = (uint8_t(*)(void))udi_hww_getsetting,
	.sof_notify = NULL,
};


static bool udi_hww_b_report_in_free;
COMPILER_WORD_ALIGNED static uint8_t udi_hww_rate;
COMPILER_WORD_ALIGNED static uint8_t udi_hww_protocol;
COMPILER_WORD_ALIGNED static uint8_t udi_hww_report_in[UDI_HID_REPORT_IN_SIZE];
COMPILER_WORD_ALIGNED static uint8_t udi_hww_report_out[UDI_HID_REPORT_OUT_SIZE];
COMPILER_WORD_ALIGNED static uint8_t udi_hww_report_feature[UDI_HID_REPORT_FEATURE_SIZE];


//! HID report descriptor
// If change length, need to change `udi_hww_report_desc_t` in:
// `drivers/common/services/usb/class/hid/device/hww/udi_hww.h`
UDC_DESC_STORAGE udi_hww_report_desc_t udi_hww_report_desc = { {
	0x06, 0xff, 0xff,   // USAGE_PAGE (Vendor Defined)
	0x09, 0x01,         // USAGE (U2F HID Authenticator Device)
	0xa1, 0x01,         // COLLECTION (Application)
	// In Report
    0x09, 0x20,         // USAGE (Input Report Data)
	0x15, 0x00,         // LOGICAL_MINIMUM (0)
	0x26, 0xff, 0x00,   // LOGICAL_MAXIMUM (255)
	0x75, 0x08,         // REPORT_SIZE (8)
	0x95, 0x40,         // REPORT_COUNT (64) 
	0x81, 0x02,         // INPUT (Data,Var,Abs)
	// Out Report
    0x09, 0x21,         // USAGE (Output Report Data)
	0x15, 0x00,         // LOGICAL_MINIMUM (0)
	0x26, 0xff, 0x00,   // LOGICAL_MAXIMUM (255)
	0x75, 0x08,         // REPORT_SIZE (8)
	0x95, 0x40,         // REPORT_COUNT (64)
	0x91, 0x02,         // OUTPUT (Data,Var,Abs)
    0xc0                // END_COLLECTION
    }
};

/**
 * \name Internal routines
 */

/**
 * \brief Send a report to HID interface
 *
 */
static bool udi_hww_setreport(void);

/**
 * \brief Initialize UDD to receive setfeature data
 */
static void udi_hww_setfeature_valid(void);

/**
 * \brief Callback called when the report is received
 *
 * \param status     UDD_EP_TRANSFER_OK, if transfer is completed
 * \param status     UDD_EP_TRANSFER_ABORT, if transfer is aborted
 * \param nb_sent    number of data received
 */
static void udi_hww_report_out_received(udd_ep_status_t status,
		iram_size_t nb_received, udd_ep_id_t ep);

/**
 * \brief Enable reception of out report
 *
 * \return \c 1 if function was successfully done, otherwise \c 0.
 */
static bool udi_hww_report_out_enable(void);

/**
 * \brief Callback called when the report is sent
 *
 * \param status     UDD_EP_TRANSFER_OK, if transfer is completed
 * \param status     UDD_EP_TRANSFER_ABORT, if transfer is aborted
 * \param nb_sent    number of data transfered
 */
static void udi_hww_report_in_sent(udd_ep_status_t status,
		iram_size_t nb_sent, udd_ep_id_t ep);


//--------------------------------------------
//------ Interface for UDI HID level

bool udi_hww_enable(void)
{
	// Initialize internal values
	udi_hww_rate = 0;
	udi_hww_protocol = 0;
	udi_hww_b_report_in_free = true;
	if (!udi_hww_report_out_enable())
		return false;
	return UDI_HWW_ENABLE_EXT();
}


void udi_hww_disable(void)
{
	UDI_HWW_DISABLE_EXT();
}


bool udi_hww_setup(void)
{
	return udi_hid_setup(&udi_hww_rate,
								&udi_hww_protocol,
								(uint8_t *) &udi_hww_report_desc,
								udi_hww_setreport);
}


uint8_t udi_hww_getsetting(void)
{
	return 0;
}


static bool udi_hww_setreport(void)
{
	if ((USB_HID_REPORT_TYPE_FEATURE == (udd_g_ctrlreq.req.wValue >> 8))
			&& (0 == (0xFF & udd_g_ctrlreq.req.wValue))
			&& (sizeof(udi_hww_report_feature) ==
					udd_g_ctrlreq.req.wLength)) {
		// Feature type on report ID 0
		udd_g_ctrlreq.payload =
				(uint8_t *) & udi_hww_report_feature;
		udd_g_ctrlreq.callback = udi_hww_setfeature_valid;
		udd_g_ctrlreq.payload_size =
				sizeof(udi_hww_report_feature);
		return true;
	}
	return false;
}


//--------------------------------------------
//------ Interface for application

bool udi_hww_send_report_in(uint8_t *data)
{
	if (!udi_hww_b_report_in_free)
		return false;
	irqflags_t flags = cpu_irq_save();
	// Fill report
	memset(&udi_hww_report_in, 0,
			sizeof(udi_hww_report_in));
	memcpy(&udi_hww_report_in, data,
	      		sizeof(udi_hww_report_in));
	udi_hww_b_report_in_free =
			!udd_ep_run(UDI_HWW_EP_IN,
							false,
							(uint8_t *) & udi_hww_report_in,
							sizeof(udi_hww_report_in),
							udi_hww_report_in_sent);
	cpu_irq_restore(flags);
	return !udi_hww_b_report_in_free;

}


//--------------------------------------------
//------ Internal routines

static void udi_hww_setfeature_valid(void)
{
	if (sizeof(udi_hww_report_feature) != udd_g_ctrlreq.payload_size)
		return;	// Bad data
	UDI_HID_SET_FEATURE(udi_hww_report_feature);
}


static void udi_hww_report_out_received(udd_ep_status_t status,
		iram_size_t nb_received, udd_ep_id_t ep)
{
	UNUSED(ep);
	if (UDD_EP_TRANSFER_OK != status)
		return;	// Abort reception

	if (sizeof(udi_hww_report_out) == nb_received) {
		UDI_HWW_REPORT_OUT(udi_hww_report_out);
	}
	udi_hww_report_out_enable();
}


static bool udi_hww_report_out_enable(void)
{
	return udd_ep_run(UDI_HWW_EP_OUT,
						false,
						(uint8_t *) & udi_hww_report_out,
						sizeof(udi_hww_report_out),
						udi_hww_report_out_received);
}


static void udi_hww_report_in_sent(udd_ep_status_t status,
		iram_size_t nb_sent, udd_ep_id_t ep)
{
	UNUSED(status);
	UNUSED(nb_sent);
	UNUSED(ep);
	udi_hww_b_report_in_free = true;
    UDI_HID_REPORT_SENT();
}
