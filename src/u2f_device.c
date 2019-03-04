/*

 The MIT License (MIT)

 Copyright (c) 2016-2017 Douglas J. Bakkum, Shift Devices AG

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

#include "bip32.h"
#include "touch.h"
#include "ecc.h"
#include "usb.h"
#include "led.h"
#include "sha2.h"
#include "hmac.h"
#include "flags.h"
#include "utils.h"
#include "memory.h"
#include "wallet.h"
#include "random.h"
#include "version.h"
#include "systick.h"
#include "commander.h"

#include "u2f/u2f.h"
#include "u2f/u2f_hid.h"
#include "u2f/u2f_keys.h"
#include "u2f_device.h"


#define APDU_LEN(A)              (uint32_t)(((A).lc1 << 16) + ((A).lc2 << 8) + ((A).lc3))
#define U2F_TIMEOUT              500// [msec]
#define U2F_KEYHANDLE_LEN        (U2F_NONCE_LENGTH + SHA256_DIGEST_LENGTH)
#define U2F_READBUF_MAX_LEN      COMMANDER_REPORT_SIZE// Max allowed by U2F specification = (57 + 128 * 59) = 7609.
// In practice, U2F commands do not need this much space.
// Therefore, reduce to save MCU memory.


#if (U2F_EC_KEY_SIZE != SHA256_DIGEST_LENGTH) || (U2F_EC_KEY_SIZE != U2F_NONCE_LENGTH)
#error "Incorrect macro values for u2f_device"
#endif


static uint32_t cid = 0;
volatile bool u2f_state_continue = false;
volatile uint16_t u2f_current_time_ms = 0;
const uint8_t U2F_HIJACK_CODE[U2F_HIJACK_ORIGIN_TOTAL][U2F_APPID_SIZE] = {
    {
        /* Corresponds to U2F client challenge filled with `0xdb` */
        /* Origin `https://digitalbitbox.com` */
        0x17, 0x9d, 0xc3, 0x1c, 0x3a, 0xd4, 0x0f, 0x05,
        0xf0, 0x71, 0x71, 0xed, 0xf4, 0x46, 0x4a, 0x71,
        0x0a, 0x2d, 0xd4, 0xde, 0xc7, 0xe6, 0x14, 0x41,
        0xc5, 0xbd, 0x24, 0x97, 0x8a, 0x99, 0x2a, 0x1a,
    }, {
        /* Origin `https://www.myetherwallet.com` */
        0x8e, 0x57, 0xf6, 0x48, 0xb9, 0x1b, 0x24, 0xfe,
        0x27, 0x92, 0x3a, 0x75, 0xef, 0xa1, 0xd0, 0x62,
        0xdc, 0xb5, 0x4d, 0x41, 0xfd, 0x0b, 0xee, 0x33,
        0x9e, 0xf2, 0xa2, 0xb4, 0x55, 0x0c, 0xbe, 0x05,
    }, {
        /* Origin `https://vintage.myetherwallet.com` */
        0x0f, 0x5b, 0x76, 0xef, 0x29, 0x8f, 0x15, 0x0b,
        0x4d, 0x39, 0x9d, 0x2c, 0x3c, 0xb9, 0x0e, 0x86,
        0x54, 0xa3, 0x7c, 0x60, 0x5f, 0x73, 0x35, 0x68,
        0xee, 0x68, 0xec, 0x41, 0x48, 0x8d, 0x53, 0x14,
    }, {
        /* Origin `https://mycrypto.com` */
        0xbd, 0x22, 0x66, 0x24, 0x02, 0x18, 0x8c, 0x4d,
        0xba, 0x4b, 0xb3, 0xd7, 0xe3, 0x98, 0x00, 0x7c,
        0x5b, 0x98, 0x6f, 0x46, 0x27, 0x1f, 0x6d, 0xf9,
        0x2e, 0x24, 0x01, 0xa7, 0xce, 0xfd, 0x1a, 0xa8,
    }
};

typedef struct {
    uint8_t reserved;
    uint8_t appId[U2F_APPID_SIZE];
    uint8_t challenge[U2F_NONCE_LENGTH];
    uint8_t keyHandle[U2F_KEYHANDLE_LEN];
    uint8_t pubKey[U2F_EC_POINT_SIZE];
} U2F_REGISTER_SIG_STR;


typedef struct {
    uint8_t appId[U2F_APPID_SIZE];
    uint8_t flags;
    uint8_t ctr[4];
    uint8_t challenge[U2F_NONCE_LENGTH];
} U2F_AUTHENTICATE_SIG_STR;


typedef struct {
    uint8_t buf[U2F_READBUF_MAX_LEN];
    uint8_t *buf_ptr;
    uint32_t len;
    uint8_t seq;
    uint8_t cmd;
} U2F_ReadBuffer;


static U2F_ReadBuffer reader;


static uint32_t next_cid(void)
{
    do {
        cid = random_uint32(0);
    } while (cid == 0 || cid == U2FHID_CID_BROADCAST);
    return cid;
}


void u2f_send_message(const uint8_t *data, const uint32_t len)
{
    usb_reply_queue_load_msg(U2FHID_MSG, data, len, cid);
}


void u2f_send_err_hid(uint32_t fcid, uint8_t err)
{
    USB_FRAME f;

    utils_zero(&f, sizeof(f));
    f.cid = fcid;
    f.init.cmd = U2FHID_ERROR;
    f.init.bcntl = 1;
    f.init.data[0] = err;
    usb_reply_queue_add(&f);
}


static void u2f_send_error(const uint16_t err)
{
    uint8_t data[2];
    data[0] = err >> 8 & 0xFF;
    data[1] = err & 0xFF;
    u2f_send_message(data, 2);
}


static void u2f_device_version(const USB_APDU *a)
{
    if (APDU_LEN(*a) != 0) {
        u2f_send_error(U2F_SW_WRONG_LENGTH);
        return;
    }

    static const uint8_t version_response[] = {'U', '2', 'F',  '_', 'V', '2', 0x90, 0x00};
    u2f_send_message(version_response, sizeof(version_response));
}


static void u2f_keyhandle_gen(const uint8_t *appId, uint8_t *nonce, uint8_t *privkey,
                              uint8_t *mac)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    for (;;) {
        hmac_sha256(appId, U2F_APPID_SIZE, memory_report_master_u2f(), 32, hash);
        hmac_sha256(hash, SHA256_DIGEST_LENGTH, nonce, U2F_NONCE_LENGTH, privkey);
        hmac_sha256(hash, SHA256_DIGEST_LENGTH, privkey, U2F_EC_KEY_SIZE, mac);

        if (ecc_isValid(privkey, ECC_SECP256r1)) {
            break;
        }

        memcpy(nonce, mac, U2F_NONCE_LENGTH);
    }
}


static void u2f_device_register(const USB_APDU *a)
{
    const U2F_REGISTER_REQ *req = (const U2F_REGISTER_REQ *)a->data;

    if (APDU_LEN(*a) != sizeof(U2F_REGISTER_REQ)) {
        u2f_send_error(U2F_SW_WRONG_LENGTH);
        return;
    }

    if (touch_button_press(DBB_TOUCH_TIMEOUT) != DBB_TOUCHED) {
        u2f_send_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
        return;

    } else {

        uint8_t privkey[U2F_EC_KEY_SIZE], nonce[U2F_NONCE_LENGTH];
        uint8_t mac[SHA256_DIGEST_LENGTH], sig[64];
        uint8_t data[sizeof(U2F_REGISTER_RESP) + 2];
        U2F_REGISTER_SIG_STR sig_base;
        U2F_REGISTER_RESP *resp = (U2F_REGISTER_RESP *)&data;
        utils_zero(data, sizeof(data));

        if (random_bytes(nonce, sizeof(nonce), 0) == DBB_ERROR) {
            u2f_send_error(U2F_SW_WRONG_DATA);
            return;
        }

        u2f_keyhandle_gen(req->appId, nonce, privkey, mac);

        ecc_get_public_key65(privkey, (uint8_t *)&resp->pubKey, ECC_SECP256r1);

        resp->registerId = U2F_REGISTER_ID;
        resp->keyHandleLen = U2F_KEYHANDLE_LEN;

        memcpy(resp->keyHandleCertSig, mac, sizeof(mac));
        memcpy(resp->keyHandleCertSig + sizeof(mac), nonce, sizeof(nonce));
        memcpy(resp->keyHandleCertSig + resp->keyHandleLen, U2F_ATT_CERT, sizeof(U2F_ATT_CERT));

        // Add signature using attestation key
        sig_base.reserved = 0;
        memcpy(sig_base.appId, req->appId, U2F_APPID_SIZE);
        memcpy(sig_base.challenge, req->challenge, U2F_NONCE_LENGTH);
        memcpy(sig_base.keyHandle, &resp->keyHandleCertSig, U2F_KEYHANDLE_LEN);
        memcpy(sig_base.pubKey, &resp->pubKey, U2F_EC_POINT_SIZE);

        if (ecc_sign(U2F_ATT_PRIV_KEY, (uint8_t *)&sig_base, sizeof(sig_base), sig,
                     NULL, ECC_SECP256r1)) {
            u2f_send_error(U2F_SW_WRONG_DATA);
            return;
        }

        uint8_t *resp_sig = resp->keyHandleCertSig + resp->keyHandleLen + sizeof(U2F_ATT_CERT);

        const uint8_t sig_len = ecc_sig_to_der(sig, resp_sig);

        // Append success bytes
        memcpy(resp->keyHandleCertSig + resp->keyHandleLen + sizeof(U2F_ATT_CERT) + sig_len,
               "\x90\x00", 2);

        int len = 1 /* registerId */ + U2F_EC_POINT_SIZE +
                  1 /* keyhandleLen */ + resp->keyHandleLen +
                  sizeof(U2F_ATT_CERT) + sig_len + 2;

        u2f_send_message(data, len);
    }
}


static void u2f_device_hijack(const U2F_AUTHENTICATE_REQ *req)
{
    static char hijack_cmd[COMMANDER_REPORT_SIZE] = {0};

    const uint32_t ctr = memory_u2f_count_iter();
    char empty_report[3 + U2F_CTR_SIZE] = {0};// 1-byte flag | 4-byte ctr | 2-byte status
    char *report;
    int report_len;

    size_t kh_len = MIN(U2F_MAX_KH_SIZE - 2, strlens((const char *)req->keyHandle + 2));
    uint8_t tot = req->keyHandle[0];
    uint8_t cnt = req->keyHandle[1];
    size_t idx = cnt * (U2F_MAX_KH_SIZE - 2);

    if (idx + kh_len < sizeof(hijack_cmd)) {
        memcpy(hijack_cmd + idx, req->keyHandle + 2, kh_len);
        hijack_cmd[idx + kh_len] = '\0';
    }

    if (cnt + 1 < tot) {
        // Need more data. Acknowledge by returning an empty report.
        report = empty_report;
        report_len = sizeof(empty_report);
    } else {
        led_blink();
        report = commander(hijack_cmd);
        report_len = MIN(strlens(report) + sizeof(empty_report), COMMANDER_REPORT_SIZE);
        memmove(report + 1 + U2F_CTR_SIZE, report, MIN(strlens(report),
                COMMANDER_REPORT_SIZE - U2F_CTR_SIZE - 1));
        memset(hijack_cmd, 0, sizeof(hijack_cmd));
    }

    report[0] = 0;// Flags
    report[1] = (ctr >> 24) & 0xff;
    report[2] = (ctr >> 16) & 0xff;
    report[3] = (ctr >> 8) & 0xff;
    report[4] = ctr & 0xff;

    // Append success bytes so that response gets through U2F client code.
    // Otherwise, the client will resend sign requests until timing out.
    // Errors encoded in JSON-formatted report.
    memcpy(report + report_len - 2, "\x90\x00", 2);
    u2f_send_message((const uint8_t *)report, report_len);
}


static void u2f_device_authenticate(const USB_APDU *a)
{
    uint8_t privkey[U2F_EC_KEY_SIZE], nonce[U2F_NONCE_LENGTH], mac[SHA256_DIGEST_LENGTH],
            sig[64], i;
    const U2F_AUTHENTICATE_REQ *req = (const U2F_AUTHENTICATE_REQ *)a->data;
    U2F_AUTHENTICATE_SIG_STR sig_base;

    if (APDU_LEN(*a) < U2F_KEYHANDLE_LEN) { // actual size could vary
        u2f_send_error(U2F_SW_WRONG_LENGTH);
        return;
    }

    for (i = 0; i < U2F_HIJACK_ORIGIN_TOTAL; i++) {
        // As an alternative interface, hijack the U2F AUTH key handle data field.
        // Slower but works in browsers for specified sites without requiring an extension.
        if (MEMEQ(req->appId, U2F_HIJACK_CODE[i], U2F_APPID_SIZE)) {
            if (!(memory_report_ext_flags() & MEM_EXT_MASK_U2F_HIJACK)) {
                // Abort U2F hijack commands if the U2F_hijack bit is not set (== disabled).
                u2f_send_err_hid(cid, U2FHID_ERR_CHANNEL_BUSY);
            } else {
                u2f_device_hijack(req);
            }
            return;
        }
    }

    if (req->keyHandleLen != U2F_KEYHANDLE_LEN) {
        u2f_send_error(U2F_SW_WRONG_DATA);
        return;
    }

    memcpy(nonce, req->keyHandle + sizeof(mac), sizeof(nonce));

    u2f_keyhandle_gen(req->appId, nonce, privkey, mac);

    if (!MEMEQ(req->keyHandle, mac, SHA256_DIGEST_LENGTH)) {
        u2f_send_error(U2F_SW_WRONG_DATA);
        return;
    }

    if (a->p1 == U2F_AUTH_CHECK_ONLY) {
        u2f_send_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
        return;
    }

    if (a->p1 != U2F_AUTH_ENFORCE) {
        u2f_send_error(U2F_SW_WRONG_DATA);
        return;
    }

    if (touch_button_press(DBB_TOUCH_TIMEOUT) != DBB_TOUCHED) {
        u2f_send_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
        return;

    } else {
        uint8_t buf[sizeof(U2F_AUTHENTICATE_RESP) + 2];
        U2F_AUTHENTICATE_RESP *resp =
            (U2F_AUTHENTICATE_RESP *)&buf;

        const uint32_t ctr = memory_u2f_count_iter();
        resp->flags = U2F_AUTH_FLAG_TUP;
        resp->ctr[0] = (ctr >> 24) & 0xff;
        resp->ctr[1] = (ctr >> 16) & 0xff;
        resp->ctr[2] = (ctr >> 8) & 0xff;
        resp->ctr[3] = ctr & 0xff;

        // Sign
        memcpy(sig_base.appId, req->appId, U2F_APPID_SIZE);
        sig_base.flags = resp->flags;
        memcpy(sig_base.ctr, resp->ctr, 4);
        memcpy(sig_base.challenge, req->challenge, U2F_NONCE_LENGTH);

        if (ecc_sign(privkey, (uint8_t *)&sig_base, sizeof(sig_base), sig, NULL, ECC_SECP256r1)) {
            u2f_send_error(U2F_SW_WRONG_DATA);
            return;
        }

        const uint8_t sig_len = ecc_sig_to_der(sig, resp->sig);

        // Append success bytes
        memcpy(buf + sizeof(U2F_AUTHENTICATE_RESP) - U2F_MAX_EC_SIG_SIZE + sig_len, "\x90\x00",
               2);

        u2f_send_message(buf, sizeof(U2F_AUTHENTICATE_RESP) - U2F_MAX_EC_SIG_SIZE + sig_len + 2);
    }
}


static void u2f_device_reset_state(void)
{
    memset(&reader, 0, sizeof(reader));
    u2f_state_continue = false;
}


static void u2f_device_ping(const uint8_t *buf, uint32_t len)
{
    usb_reply_queue_load_msg(U2FHID_PING, buf, len, cid);
}


static void u2f_device_wink(const uint8_t *buf, uint32_t len)
{
    (void)buf;

    if (len > 0) {
        u2f_send_err_hid(cid, U2FHID_ERR_INVALID_LEN);
        return;
    }

    led_blink();

    USB_FRAME f;
    utils_zero(&f, sizeof(f));
    f.cid = cid;
    f.init.cmd = U2FHID_WINK;
    f.init.bcntl = 0;
    usb_reply_queue_add(&f);
}


static void u2f_device_sync(const uint8_t *buf, uint32_t len)
{
    // TODO - implement
    (void) buf;
    (void) len;
}


static void u2f_device_lock(const uint8_t *buf, uint32_t len)
{
    // TODO - implement
    (void) buf;
    (void) len;
}


static void u2f_device_init(const USB_FRAME *in)
{
    const U2FHID_INIT_REQ *init_req = (const U2FHID_INIT_REQ *)&in->init.data;
    USB_FRAME f;
    U2FHID_INIT_RESP resp;

    if (in->cid == 0) {
        u2f_send_err_hid(in->cid, U2FHID_ERR_INVALID_CID);
        return;
    }

    utils_zero(&f, sizeof(f));
    f.cid = in->cid;
    f.init.cmd = U2FHID_INIT;
    f.init.bcnth = 0;
    f.init.bcntl = U2FHID_INIT_RESP_SIZE;

    utils_zero(&resp, sizeof(resp));
    memcpy(resp.nonce, init_req->nonce, sizeof(init_req->nonce));
    resp.cid = in->cid == U2FHID_CID_BROADCAST ? next_cid() : in->cid;
    resp.versionInterface = U2FHID_IF_VERSION;
    resp.versionMajor = DIGITAL_BITBOX_VERSION_MAJOR;
    resp.versionMinor = DIGITAL_BITBOX_VERSION_MINOR;
    resp.versionBuild = DIGITAL_BITBOX_VERSION_PATCH;
    resp.capFlags = U2FHID_CAPFLAG_WINK;
    memcpy(&f.init.data, &resp, sizeof(resp));
    usb_reply_queue_add(&f);
}


static void u2f_device_msg(const USB_APDU *a, uint32_t len)
{
    if ((APDU_LEN(*a) + sizeof(USB_APDU)) > len) {
        return;
    }

    if (a->cla != 0) {
        u2f_send_error(U2F_SW_CLA_NOT_SUPPORTED);
        return;
    }

    switch (a->ins) {
        case U2F_REGISTER:
            u2f_device_register(a);
            break;
        case U2F_AUTHENTICATE:
            u2f_device_authenticate(a);
            break;
        case U2F_VERSION:
            u2f_device_version(a);
            break;
        default:
            u2f_send_error(U2F_SW_INS_NOT_SUPPORTED);
    }
}


static void u2f_device_cmd_cont(const USB_FRAME *f)
{
    (void) f;

    if ((reader.buf_ptr - reader.buf) < (signed)reader.len) {
        // Need more data
        return;
    }

    u2f_state_continue = false;

    if ( (reader.cmd < U2FHID_VENDOR_FIRST) &&
            !(memory_report_ext_flags() & MEM_EXT_MASK_U2F) ) {
        // Abort U2F commands if the U2F bit is not set (==U2F disabled).
        // Vendor specific commands are passed through.
        u2f_send_err_hid(cid, U2FHID_ERR_CHANNEL_BUSY);
    } else {
        // Received all data
        switch (reader.cmd) {
            case U2FHID_PING:
                u2f_device_ping(reader.buf, reader.len);
                break;
            case U2FHID_MSG:
                u2f_device_msg((USB_APDU *)reader.buf, reader.len);
                break;
            case U2FHID_WINK:
                u2f_device_wink(reader.buf, reader.len);
                break;
            case U2FHID_HWW: {
                char *report;
                reader.buf[MIN(reader.len, sizeof(reader.buf) - 1)] = '\0';// NULL terminate
                report = commander((const char *)reader.buf);
                usb_reply_queue_load_msg(U2FHID_HWW, (const uint8_t *)report, strlens(report), cid);
                break;
            }
            default:
                u2f_send_err_hid(cid, U2FHID_ERR_INVALID_CMD);
                break;
        }
    }

    // Finished
    u2f_device_reset_state();
    cid = 0;
}


static void u2f_device_cmd_init(const USB_FRAME *f)
{
    if (f->cid == U2FHID_CID_BROADCAST || f->cid == 0) {
        u2f_send_err_hid(f->cid, U2FHID_ERR_INVALID_CID);
        return;
    }

    if ((unsigned)U2FHID_MSG_LEN(*f) > sizeof(reader.buf)) {
        u2f_send_err_hid(f->cid, U2FHID_ERR_INVALID_LEN);
        return;
    }

    memset(&reader, 0, sizeof(reader));
    reader.seq = 0;
    reader.buf_ptr = reader.buf;
    reader.len = U2FHID_MSG_LEN(*f);
    reader.cmd = f->type;
    memcpy(reader.buf_ptr, f->init.data, sizeof(f->init.data));
    reader.buf_ptr += sizeof(f->init.data);
    cid = f->cid;

    u2f_current_time_ms = 0;
    u2f_state_continue = true;
    u2f_device_cmd_cont(f);
}


void u2f_device_run(const USB_FRAME *f)
{
    if ((f->type & U2FHID_TYPE_MASK) == U2FHID_TYPE_INIT) {

        if (f->init.cmd == U2FHID_INIT) {
            u2f_device_init(f);
            if (f->cid == cid) {
                u2f_device_reset_state();
            }
        } else if (u2f_state_continue) {
            if (f->cid == cid) {
                usb_reply_queue_clear();
                u2f_device_reset_state();
                u2f_send_err_hid(f->cid, U2FHID_ERR_INVALID_SEQ);
            } else {
                u2f_send_err_hid(f->cid, U2FHID_ERR_CHANNEL_BUSY);
            }
        } else {
            u2f_device_cmd_init(f);
        }
        goto exit;
    }

    if ((f->type & U2FHID_TYPE_MASK) == U2FHID_TYPE_CONT) {

        if (!u2f_state_continue) {
            goto exit;
        }

        if (cid != f->cid) {
            u2f_send_err_hid(f->cid, U2FHID_ERR_CHANNEL_BUSY);
            goto exit;
        }

        if (reader.seq != f->cont.seq) {
            usb_reply_queue_clear();
            u2f_device_reset_state();
            u2f_send_err_hid(f->cid, U2FHID_ERR_INVALID_SEQ);
            goto exit;
        }

        // Check bounds
        if ((reader.buf_ptr - reader.buf) >= (signed) reader.len
                || (reader.buf_ptr + sizeof(f->cont.data) - reader.buf) > (signed) sizeof(
                    reader.buf)) {
            goto exit;
        }

        reader.seq++;
        memcpy(reader.buf_ptr, f->cont.data, sizeof(f->cont.data));
        reader.buf_ptr += sizeof(f->cont.data);
        u2f_device_cmd_cont(f);
    }

exit:
    usb_reply_queue_send();
}


void u2f_device_timeout(void)
{
    if (!u2f_state_continue) {
        return;
    }

    u2f_current_time_ms += 40;

    if (u2f_current_time_ms > U2F_TIMEOUT) {
        u2f_device_reset_state();
        u2f_send_err_hid(cid, U2FHID_ERR_MSG_TIMEOUT);
        usb_reply_queue_send();
    }
}

