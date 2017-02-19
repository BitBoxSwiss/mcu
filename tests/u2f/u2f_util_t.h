// Copyright 2014 Google Inc. All rights reserved.
// Copyright 2017 Douglas J. Bakkum, Shift Devices AG
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd


#ifndef __U2F_UTIL_H_INCLUDED__
#define __U2F_UTIL_H_INCLUDED__


#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>

#include "u2f/u2f.h"
#include "u2f/u2f_hid.h"
#include "usb.h"


#ifndef CONTINUOUS_INTEGRATION
#include <hidapi.h>
#else
typedef void hid_device;
#endif


#define CHECK_EQ(a,b) do { if ((a)!=(b)) { printf("\x1b[31mCHECK_EQ fail at %s()[%d] %f != %f\x1b[0m \n", __func__, __LINE__, a*1.0, b*1.0); abort();}} while(0)
#define CHECK_NE(a,b) do { if ((a)==(b)) { printf("\x1b[31mCHECK_NE fail at %s()[%d] %f == %f\x1b[0m \n", __func__, __LINE__, a*1.0, b*1.0); abort();}} while(0)
#define CHECK_GE(a,b) do { if ((a)<(b))  { printf("\x1b[31mCHECK_GE fail at %s()[%d] %f <= %f\x1b[0m \n", __func__, __LINE__, a*1.0 ,b*1.0); abort();}} while(0)
#define CHECK_GT(a,b) do { if ((a)<=(b)) { printf("\x1b[31mCHECK_GT fail at %s()[%d] %f  < %f\x1b[0m \n", __func__, __LINE__, a*1.0 ,b*1.0); abort();}} while(0)
#define CHECK_LT(a,b) do { if ((a)>=(b)) { printf("\x1b[31mCHECK_LT fail at %s()[%d] %f >= %f\x1b[0m \n", __func__, __LINE__, a*1.0 ,b*1.0); abort();}} while(0)
#define CHECK_LE(a,b) do { if ((a)>(b))  { printf("\x1b[31mCHECK_LE fail at %s()[%d] %f  > %f\x1b[0m \n", __func__, __LINE__, a*1.0 ,b*1.0); abort();}} while(0)
#define PASS(x)  do { (x); printf("\x1b[32mPASS("#x")\x1b[0m \n");} while(0)


void U2Fob_testLiveDevice(uint8_t test);
uint8_t U2Fob_liveDeviceTesting(void);
float U2Fob_deltaTime(uint64_t *state);

struct U2Fob {
    hid_device *dev;
    char *path;
    uint32_t cid;
    uint8_t nonce[U2FHID_INIT_NONCE_SIZE];
};

struct U2Fob *U2Fob_create(void);
void U2Fob_destroy(struct U2Fob *device);
int U2Fob_open(struct U2Fob *device);
void U2Fob_close(struct U2Fob *device);
int U2Fob_reopen(struct U2Fob *device);
int U2Fob_init(struct U2Fob *device);
uint32_t U2Fob_getCid(struct U2Fob *device);
int U2Fob_sendHidFrame(struct U2Fob *device, USB_FRAME *out);
int U2Fob_receiveHidFrame(struct U2Fob *device, USB_FRAME *in,
                          float timeoutSeconds);
int U2Fob_send(struct U2Fob *device, uint8_t cmd,
               const void *data, size_t size);
int U2Fob_recv(struct U2Fob *device, uint8_t *cmd,
               void *data, size_t size,
               float timeoutSeconds);

// Exchanges a pre-formatted APDU buffer with the device.
// returns
//   negative error
//   positive sw12, e.g. 0x9000, 0x6985 etc.
int U2Fob_exchange_apdu_buffer(struct U2Fob *device,
                               void *data,
                               size_t size,
                               char *in,
                               size_t *in_len);

// Formats an APDU with the given field values, and exchanges it
// with the device.
// returns
//   negative error
//   positive sw12, e.g. 0x9000, 0x6985 etc.
int U2Fob_apdu(struct U2Fob *device,
               uint8_t CLA, uint8_t INS, uint8_t P1, uint8_t P2,
               const char *out, size_t out_len,
               char *in, size_t *in_len);

bool getCertificate(const U2F_REGISTER_RESP rsp, char *cert, size_t *cert_len);
bool getSignature(const U2F_REGISTER_RESP rsp, char *sig, size_t *sig_len);
bool getSubjectPublicKey(const char *cert, size_t cert_len, char *pk, size_t *pk_len);
bool getCertSignature(const char *cert, size_t cert_len, char *sig, size_t *sig_len);
bool verifyCertificate(const char *pk, const char *cert);


#endif  // __U2F_UTIL_H_INCLUDED__

