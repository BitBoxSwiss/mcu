/*

 The MIT License (MIT)

 Copyright (c) 2016 Douglas J. Bakkum, Shift Devices AG

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


#define APDU_LEN(A)        (uint32_t)(((A).lc1 << 16) + ((A).lc2 << 8) + ((A).lc3))
#define U2F_TIMEOUT        500// [msec]
#define U2F_NONCE_LENGTH   32
#define U2F_KEYHANDLE_LEN  (U2F_NONCE_LENGTH + SHA256_DIGEST_LENGTH)

#if (U2F_EC_KEY_SIZE != SHA256_DIGEST_LENGTH) || (U2F_EC_KEY_SIZE != U2F_NONCE_LENGTH)
#error "Incorrect macro values for u2f_device"
#endif


static uint32_t cid = 0;
volatile bool u2f_state_continue = false;
volatile uint16_t u2f_current_time_ms = 0;


typedef struct {
    uint8_t reserved;
    uint8_t appId[U2F_APPID_SIZE];
    uint8_t chal[U2F_CHAL_SIZE];
    uint8_t keyHandle[U2F_KEYHANDLE_LEN];
    uint8_t pubKey[U2F_EC_POINT_SIZE];
} U2F_REGISTER_SIG_STR;


typedef struct {
    uint8_t appId[U2F_APPID_SIZE];
    uint8_t flags;
    uint8_t ctr[4];
    uint8_t chal[U2F_CHAL_SIZE];
} U2F_AUTHENTICATE_SIG_STR;


typedef struct {
    uint8_t buf[57 + 128 * 59];
    uint8_t *buf_ptr;
    uint32_t len;
    uint8_t seq;
    uint8_t cmd;
} U2F_ReadBuffer;

static U2F_ReadBuffer *reader;


static uint32_t next_cid(void)
{
    do {
        cid = random_uint32(0);
    } while (cid == 0 || cid == CID_BROADCAST);
    return cid;
}


static void u2f_send_message(const uint8_t *data, const uint32_t len)
{
    usb_reply_queue_load_msg(U2FHID_MSG, data, len, cid);
}


static void u2f_send_err_hid(uint32_t fcid, uint8_t err)
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

    if (touch_button_press(DBB_TOUCH_LONG) != DBB_TOUCHED) {
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
        memcpy(sig_base.chal, req->chal, U2F_CHAL_SIZE);
        memcpy(sig_base.keyHandle, &resp->keyHandleCertSig, U2F_KEYHANDLE_LEN);
        memcpy(sig_base.pubKey, &resp->pubKey, U2F_EC_POINT_SIZE);

        if (ecc_sign(U2F_ATT_PRIV_KEY, (uint8_t *)&sig_base, sizeof(sig_base), sig,
                     ECC_SECP256r1)) {
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


static void u2f_device_authenticate(const USB_APDU *a)
{
    uint8_t privkey[U2F_EC_KEY_SIZE], nonce[U2F_NONCE_LENGTH], mac[SHA256_DIGEST_LENGTH],
            sig[64];
    const U2F_AUTHENTICATE_REQ *req = (const U2F_AUTHENTICATE_REQ *)a->data;
    U2F_AUTHENTICATE_SIG_STR sig_base;

    if (APDU_LEN(*a) < U2F_KEYHANDLE_LEN) { // actual size could vary
        u2f_send_error(U2F_SW_WRONG_LENGTH);
        return;
    }

    if (req->keyHandleLen != U2F_KEYHANDLE_LEN) {
        u2f_send_error(U2F_SW_WRONG_DATA);
        return;
    }

    memcpy(nonce, req->keyHandle + sizeof(mac), sizeof(nonce));

    u2f_keyhandle_gen(req->appId, nonce, privkey, mac);

    if (memcmp(req->keyHandle, mac, SHA256_DIGEST_LENGTH) != 0) {
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

    if (touch_button_press(DBB_TOUCH_LONG) != DBB_TOUCHED) {
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
        memcpy(sig_base.chal, req->chal, U2F_CHAL_SIZE);

        if (ecc_sign(privkey, (uint8_t *)&sig_base, sizeof(sig_base), sig, ECC_SECP256r1)) {
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
    reader->cmd = 0;
    reader->len = 0;
    reader->seq = 255;
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
        u2f_send_err_hid(cid, U2F_ERR_INVALID_LEN);
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
        u2f_send_err_hid(in->cid, U2F_ERR_INVALID_CID);
        return;
    }

    utils_zero(&f, sizeof(f));
    f.cid = in->cid;
    f.init.cmd = U2FHID_INIT;
    f.init.bcnth = 0;
    f.init.bcntl = U2FHID_INIT_RESP_SIZE;

    memcpy(resp.nonce, init_req->nonce, sizeof(init_req->nonce));
    resp.cid = in->cid == CID_BROADCAST ? next_cid() : in->cid;
    resp.versionInterface = U2FHID_IF_VERSION;
    resp.versionMajor = DIGITAL_BITBOX_VERSION_MAJOR;
    resp.versionMinor = DIGITAL_BITBOX_VERSION_MINOR;
    resp.versionBuild = DIGITAL_BITBOX_VERSION_PATCH;
    resp.capFlags = CAPFLAG_WINK;
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

    if ((reader->buf_ptr - reader->buf) < (signed)reader->len) {
        // Need more data
        return;
    }

    u2f_state_continue = false;

    if ( reader->cmd < U2FHID_VENDOR_FIRST &&
            ((memory_report_ext_flags() & MEM_EXT_FLAG_U2F) || (wallet_seeded() != DBB_OK)) ) {
        // Abort U2F commands if the U2F bit is set (==U2F disabled) or the wallet is not seeded.
        // Vendor specific commands are passed through.
        u2f_send_err_hid(cid, U2F_ERR_CHANNEL_BUSY);
    } else {
        // Received all data
        switch (reader->cmd) {
            case U2FHID_PING:
                u2f_device_ping(reader->buf, reader->len);
                break;
            case U2FHID_MSG:
                u2f_device_msg((USB_APDU *)reader->buf, reader->len);
                break;
            case U2FHID_WINK:
                u2f_device_wink(reader->buf, reader->len);
                break;
            case HWW_COMMAND:
                reader->buf[MIN(reader->len,
                                sizeof(reader->buf) - 1)] = '\0';// NULL terminate// FIXME - needed?
                char *report = commander((const char *)reader->buf);
                usb_reply_queue_load_msg(HWW_COMMAND, (const uint8_t *)report, strlens(report), cid);
                break;
            default:
                u2f_send_err_hid(cid, U2F_ERR_INVALID_CMD);
                break;
        }
    }

    // Finished
    u2f_device_reset_state();
    reader = 0;
    cid = 0;
}


static void u2f_device_cmd_init(const USB_FRAME *f)
{
    static U2F_ReadBuffer readbuffer;

    if (f->cid == CID_BROADCAST || f->cid == 0) {
        u2f_send_err_hid(f->cid, U2F_ERR_INVALID_CID);
        return;
    }

    if ((unsigned)MSG_LEN(*f) > sizeof(reader->buf)) {
        u2f_send_err_hid(f->cid, U2F_ERR_INVALID_LEN);
        return;
    }

    reader = &readbuffer;
    reader->seq = 0;
    reader->buf_ptr = reader->buf;
    reader->len = MSG_LEN(*f);
    reader->cmd = f->type;
    memcpy(reader->buf_ptr, f->init.data, sizeof(f->init.data));
    reader->buf_ptr += sizeof(f->init.data);
    cid = f->cid;

    u2f_current_time_ms = 0;
    u2f_state_continue = true;
    u2f_device_cmd_cont(f);
}


void u2f_device_run(const USB_FRAME *f)
{
    if ((f->type & TYPE_MASK) == TYPE_INIT) {

        if (f->init.cmd == U2FHID_INIT) {
            u2f_device_init(f);
            if (f->cid == cid) {
                u2f_device_reset_state();
            }
        } else if (u2f_state_continue) {
            if (f->cid == cid) {
                usb_reply_queue_clear();
                u2f_device_reset_state();
                u2f_send_err_hid(f->cid, U2F_ERR_INVALID_SEQ);
            } else {
                u2f_send_err_hid(f->cid, U2F_ERR_CHANNEL_BUSY);
            }
        } else {
            u2f_device_cmd_init(f);
        }
        goto exit;
    }

    if ((f->type & TYPE_MASK) == TYPE_CONT) {

        if (!u2f_state_continue) {
            goto exit;
        }

        if (cid != f->cid) {
            u2f_send_err_hid(f->cid, U2F_ERR_CHANNEL_BUSY);
            goto exit;
        }

        if (reader->seq != f->cont.seq) {
            usb_reply_queue_clear();
            u2f_device_reset_state();
            u2f_send_err_hid(f->cid, U2F_ERR_INVALID_SEQ);
            goto exit;
        }

        // Check bounds
        if ((reader->buf_ptr - reader->buf) >= (signed) reader->len
                || (reader->buf_ptr + sizeof(f->cont.data) - reader->buf) > (signed) sizeof(
                    reader->buf)) {
            goto exit;
        }

        reader->seq++;
        memcpy(reader->buf_ptr, f->cont.data, sizeof(f->cont.data));
        reader->buf_ptr += sizeof(f->cont.data);
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
        u2f_send_err_hid(cid, U2F_ERR_MSG_TIMEOUT);
        usb_reply_queue_send();
    }
}

