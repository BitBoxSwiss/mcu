/*

 The MIT License (MIT)

 Copyright (c) 2015-2018 Douglas J. Bakkum

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


#ifndef _API_H_
#define _API_H_


#include <arpa/inet.h>
#include "flags.h"
#include "yajl/src/api/yajl_tree.h"
#include "yajl/src/api/yajl_parse.h"
#include "u2f/u2f_hid.h"
#include "u2f/u2f.h"
#include "u2f_device.h"
#include "commander.h"
#include "cipher.h"
#include "random.h"
#include "utest.h"
#include "usb.h"


#define HWW_CID 0xff000000
#define HID_REPORT_SIZE COMMANDER_REPORT_SIZE
#define API_READ_ERROR "ERROR: Unable to read report."

#define ASSERT_JSON                                                          \
    do {                                                                     \
        yajl_callbacks callbacks = {NULL};                                   \
        yajl_handle hand = yajl_alloc(&callbacks, NULL, NULL);               \
        yajl_config(hand, yajl_allow_comments, 1);                           \
        size_t size = strlen(api_read_decrypted_report());                   \
        yajl_status err = yajl_parse(                                        \
            hand, (const unsigned char *)api_read_decrypted_report(), size); \
        u_assert(err == yajl_status_ok);                                     \
        yajl_free(hand);                                                     \
    } while (0)

#define ASSERT_SUCCESS do {\
  ASSERT_JSON;\
  u_assert_str_has(api_read_decrypted_report(), attr_str(ATTR_success));\
  u_assert_str_has_not(api_read_decrypted_report(), attr_str(ATTR_error));\
} while (0);

#define ASSERT_REPORT_HAS(a) do {\
  ASSERT_JSON;\
  u_assert_str_has(api_read_decrypted_report(), (a));\
} while (0);

#define ASSERT_REPORT_HAS_NOT(a) do {\
  ASSERT_JSON;\
  u_assert_str_has_not(api_read_decrypted_report(), (a));\
} while (0);


#ifndef CONTINUOUS_INTEGRATION
// http://www.signal11.us/oss/hidapi/
#include <hidapi.h>

static hid_device *HID_HANDLE;
#endif


static const char tests_pwd[] = "0000";
static const char hidden_pwd[] = "hide";
static uint8_t KEY_STANDARD[MEM_PAGE_LEN];
static uint8_t KEY_HIDDEN[MEM_PAGE_LEN];
static char command_sent[COMMANDER_REPORT_SIZE] = {0};
const uint8_t U2F_HIJACK_CODE[U2F_HIJACK_ORIGIN_TOTAL][U2F_APPID_SIZE];// extern
static unsigned char HID_REPORT[HID_REPORT_SIZE] = {0};
static char decrypted_report[COMMANDER_REPORT_SIZE];

static int TEST_LIVE_DEVICE = 0;
static int TEST_U2FAUTH_HIJACK = 0;


static const char *api_read_decrypted_report(void)
{
    return decrypted_report;
}


static void api_decrypt_report(const char *report, uint8_t *key)
{
    int decrypt_len;
    char *dec;

    memset(decrypted_report, 0, sizeof(decrypted_report));

    yajl_val json_node = yajl_tree_parse(report, NULL, 0);

    if (!json_node) {
        strcpy(decrypted_report, "/* error: Failed to parse report. */");
        return;
    }

    size_t i, r = json_node->u.object.len;
    for (i = 0; i < r; i++) {
        const char *ciphertext_path[] = { cmd_str(CMD_ciphertext), (const char *) 0 };
        const char *ciphertext = YAJL_GET_STRING(yajl_tree_get(json_node, ciphertext_path,
                                 yajl_t_string));
        if (ciphertext) {
            dec = cipher_aes_b64_hmac_decrypt((const unsigned char *)ciphertext, strlens(ciphertext),
                                              &decrypt_len, key);
            if (!dec) {
                strcpy(decrypted_report, "/* error: Failed to decrypt. */");
                goto exit;
            }

            sprintf(decrypted_report, "/* ciphertext */ %.*s", decrypt_len, dec);
            free(dec);
            goto exit;
        }
    }
    strcpy(decrypted_report, report);
exit:
    yajl_tree_free(json_node);
    return;
}


// Initialize a frame with len random payload, or data.
static void api_create_u2f_frame(USB_FRAME *f, uint32_t cid, uint8_t cmd, size_t len,
                                 const void *data)
{
    memset(f, 0, sizeof(USB_FRAME));
    f->cid = cid;
    f->init.cmd = cmd | U2FHID_TYPE_INIT;
    f->init.bcnth = (uint8_t) (len >> 8);
    f->init.bcntl = (uint8_t) len;
    for (size_t i = 0; i < MIN(len, sizeof(f->init.data)); ++i) {
        f->init.data[i] = data ? ((const uint8_t *)data)[i] : (random_uint32(0) & 255);
    }
}


static int api_hid_send_frame(USB_FRAME *f)
{
    int res = 0;
    uint8_t d[sizeof(USB_FRAME) + 1];
    memset(d, 0, sizeof(d));
    d[0] = 0;  // un-numbered report
    f->cid = htonl(f->cid);  // cid is in network order on the wire
    memcpy(d + 1, f, sizeof(USB_FRAME));
    f->cid = ntohl(f->cid);

    if (TEST_LIVE_DEVICE) {
#ifndef CONTINUOUS_INTEGRATION
        res = hid_write(HID_HANDLE, d, sizeof(d));
#endif
    } else {
        u2f_device_run(f);
        res = sizeof(d);
    }

    if (res == sizeof(d)) {
        return 0;
    }
    return 1;
}


static int api_hid_send_frames(uint32_t cid, uint8_t cmd, const void *data, size_t size)
{
    if (size > COMMANDER_REPORT_SIZE) {
        u_print_error("ERROR  - %s() - Line %d\n", __func__, __LINE__);
        u_print_error("\tCommand size exceeds buffer size by %lu bytes.\n",
                      (unsigned long)size - COMMANDER_REPORT_SIZE);
        return 0;
    }

    USB_FRAME frame;
    int res;
    size_t frameLen;
    uint8_t seq = 0;
    const uint8_t *pData = (const uint8_t *) data;

    frame.cid = cid;
    frame.init.cmd = U2FHID_TYPE_INIT | cmd;
    frame.init.bcnth = (size >> 8) & 255;
    frame.init.bcntl = (size & 255);

    frameLen = MIN(size, sizeof(frame.init.data));
    memset(frame.init.data, 0xEE, sizeof(frame.init.data));
    memcpy(frame.init.data, pData, frameLen);

    do {
        res = api_hid_send_frame(&frame);
        if (res != 0) {
            return res;
        }

        size -= frameLen;
        pData += frameLen;

        frame.cont.seq = seq++;
        frameLen = MIN(size, sizeof(frame.cont.data));
        memset(frame.cont.data, 0xEE, sizeof(frame.cont.data));
        memcpy(frame.cont.data, pData, frameLen);
    } while (size);

    return 0;
}


static int api_hid_read_frame(USB_FRAME *r)
{

    memset((int8_t *)r, 0xEE, sizeof(USB_FRAME));

    int res = 0;
    if (TEST_LIVE_DEVICE) {
#ifndef CONTINUOUS_INTEGRATION
        res = hid_read(HID_HANDLE, (uint8_t *) r, sizeof(USB_FRAME));
#endif
    } else {
        static uint8_t *data;
        data = usb_reply_queue_read();
        if (data) {
            memcpy(r, data, sizeof(USB_FRAME));
            res = sizeof(USB_FRAME);
        } else {
            res = 0;
        }
    }


    if (res == sizeof(USB_FRAME)) {
        if (TEST_LIVE_DEVICE) {
            r->cid = ntohl(r->cid);
        }
        return 0;
    }
    return 1;
}


static int api_hid_read_frames(uint32_t cid, uint8_t cmd, void *data, int max)
{
    USB_FRAME frame;
    int res, result;
    size_t totalLen, frameLen;
    uint8_t seq = 0;
    uint8_t *pData = (uint8_t *) data;

    (void) cmd;

    do {
        res = api_hid_read_frame(&frame);
        if (res != 0) {
            return res;
        }

    } while (frame.cid != cid || U2FHID_FRAME_TYPE(frame) != U2FHID_TYPE_INIT);

    if (frame.init.cmd == U2FHID_ERROR) {
        return -frame.init.data[0];
    }

    totalLen = MIN(max, U2FHID_MSG_LEN(frame));
    frameLen = MIN(sizeof(frame.init.data), totalLen);

    result = totalLen;

    memcpy(pData, frame.init.data, frameLen);
    totalLen -= frameLen;
    pData += frameLen;

    while (totalLen) {
        res = api_hid_read_frame(&frame);
        if (res != 0) {
            return res;
        }

        if (frame.cid != cid) {
            continue;
        }
        if (U2FHID_FRAME_TYPE(frame) != U2FHID_TYPE_CONT) {
            return -U2FHID_ERR_INVALID_SEQ;
        }
        if (U2FHID_FRAME_SEQ(frame) != seq++) {
            return -U2FHID_ERR_INVALID_SEQ;
        }

        frameLen = MIN(sizeof(frame.cont.data), totalLen);

        memcpy(pData, frame.cont.data, frameLen);
        totalLen -= frameLen;
        pData += frameLen;
    }

    return result;
}


#ifndef CONTINUOUS_INTEGRATION
static int api_hid_init(void)
{
    struct hid_device_info *devs, *cur_dev;
    devs = hid_enumerate(0x0, 0x0);
    cur_dev = devs;
    while (cur_dev) {
        if (cur_dev->vendor_id == 0x03eb && cur_dev->product_id == 0x2402) {
            if (cur_dev->interface_number == 0 || cur_dev->usage_page == 0xffff) {
                // hidapi is not consistent across platforms
                // usage_page works on Windows/Mac; interface_number works on Linux
                HID_HANDLE = hid_open_path(cur_dev->path);
                break;
            }
        }
        cur_dev = cur_dev->next;
    }
    hid_free_enumeration(devs);
    if (!HID_HANDLE) {
        return DBB_ERROR;
    }
    return DBB_OK;
}
#endif


static void api_hid_send_len(const char *cmd, int cmdlen)
{
    if (TEST_U2FAUTH_HIJACK) {
        // Vendor defined U2F commands appear to not be enabled in browsers.
        // As an alternative interface, hijack the U2F AUTH key handle data field.
        // Slower but works in browsers without requiring an extension.
        uint8_t buf[sizeof(USB_APDU) + sizeof(U2F_AUTHENTICATE_REQ)];
        USB_APDU *a = (USB_APDU *)buf;
        U2F_AUTHENTICATE_REQ *auth_req = (U2F_AUTHENTICATE_REQ *)a->data;

        int idx;
        int kh_max_len = U2F_MAX_KH_SIZE - 2;// Subtract bytes for `idx` and `total`.
        int total = cmdlen ? (1 + ((cmdlen - 1) / kh_max_len)) : 1;

        for (idx = 0; idx < total; idx++) {
            memset(buf, 0, sizeof(buf));
            a->ins = U2F_AUTHENTICATE;
            a->lc1 = 0;
            a->lc2 = (sizeof(U2F_AUTHENTICATE_REQ) >> 8) & 255;
            a->lc3 = (sizeof(U2F_AUTHENTICATE_REQ) & 255);
            auth_req->keyHandleLen = MIN(U2F_MAX_KH_SIZE, cmdlen - idx * kh_max_len + 2);
            auth_req->keyHandle[0] = total;
            auth_req->keyHandle[1] = idx;
            memcpy(auth_req->keyHandle + 2, cmd + idx * kh_max_len, MIN(kh_max_len, MAX(0,
                    cmdlen - idx * kh_max_len)));
            memcpy(auth_req->appId, U2F_HIJACK_CODE, U2F_APPID_SIZE);
            api_hid_send_frames(HWW_CID, U2FHID_MSG, buf, sizeof(buf));
        }
    } else {
        api_hid_send_frames(HWW_CID, U2FHID_HWW, cmd, cmdlen);
    }
}


static void api_hid_send(const char *cmd)
{
    api_hid_send_len(cmd, strlens(cmd));
}


static void api_hid_send_encrypt(const char *cmd, uint8_t *key)
{
    int enc_len;
    char *enc = cipher_aes_b64_hmac_encrypt((const unsigned char *)cmd, strlens(cmd),
                                            &enc_len,
                                            key);
    api_hid_send_len(enc, enc_len);
    free(enc);
}


static void api_hid_read(uint8_t *key)
{
    int res;
    int u2fhid_cmd = TEST_U2FAUTH_HIJACK ? U2FHID_MSG : U2FHID_HWW;
    memset(HID_REPORT, 0, HID_REPORT_SIZE);
    res = api_hid_read_frames(HWW_CID, u2fhid_cmd, HID_REPORT, HID_REPORT_SIZE);
    if (res < 0) {
        strcpy(decrypted_report, "/* " API_READ_ERROR " */");
        return;
    }
    if (TEST_U2FAUTH_HIJACK) {
        // If the hijack command was sent in multiple chunks, the first chunks are replied
        // with a single-byte (framed) having the value HIJACK_STATE_INCOMPLETE_COMMAND.
        //
        // After receiving the all chunks, the firware replies with a single-byte
        // HIJACK_STATE_PROCESSING_COMMAND.
        //
        // The client can poll the firmware for the JSON response by sending a single-byte
        // (framed) having any value. If the firmware is busy, for example waiting for user touch
        // button press, the firmware will reply with a single-byte HIJACK_STATE_PROCESSING_COMMAND.
        // If the firmware finished processing, the reply will contain the JSON response.
        //
        // The first 5 bytes are the frame header. The last two bytes contain the U2F status,
        // which should be the success bytes \x90\x00 in order for the U2F hijack approach
        // to work in browsers.
        char *r = (char *)(HID_REPORT + 1 + U2F_CTR_SIZE);
        r[strlens(r) - 1] = 0;
        if (strlens(r) == 1) {
            if (r[0] == HIJACK_STATE_PROCESSING_COMMAND) {
                api_hid_send(" ");
            }
            api_hid_read(key);
        } else if (strlens(r) > 1) {
            api_decrypt_report(r, key);
        } else {
            strcpy(decrypted_report, "/* " API_READ_ERROR " */");
        }
    } else {
        api_decrypt_report((char *)HID_REPORT, key);
    }
    //printf("received:  >>%s<<\n", api_read_decrypted_report());
}


static void api_send_cmd(const char *command, uint8_t *key)
{
    memset(command_sent, 0, sizeof(command_sent));
    if (command) {
        memcpy(command_sent, command, strlens(command));
    }
    if (key == NULL) {
        api_hid_send(command);
        api_hid_read(key);
    } else {
        api_hid_send_encrypt(command, key);
        api_hid_read(key);
    }
}


static void api_format_send_cmd(const char *cmd, const char *val, uint8_t *key)
{
    char command[COMMANDER_REPORT_SIZE] = {0};
    strcpy(command, "{\"");
    strcat(command, cmd);
    strcat(command, "\": ");
    if (val[0] == '{') {
        strcat(command, val);
    } else {
        strcat(command, "\"");
        strcat(command, val);
        strcat(command, "\"");
    }
    strcat(command, "}");
    api_send_cmd(command, key);
}


static void api_reset_device(void)
{
    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL); // if not set
    api_format_send_cmd(cmd_str(CMD_reset), attr_str(ATTR___ERASE__), KEY_STANDARD);
}


/**
 * @return Buffer containing the read value. Guaranteed to be nonnull.
 */
static const char *api_read_value(int cmd)
{
    static char value[HID_REPORT_SIZE];
    memset(value, 0, sizeof(value));

    yajl_val json_node = yajl_tree_parse(api_read_decrypted_report(), NULL, 0);
    if (json_node && YAJL_IS_OBJECT(json_node)) {
        const char *path[] = { cmd_str(cmd), NULL };
        const char *v = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));
        snprintf(value, sizeof(value), "%s", v);
    }

    yajl_tree_free(json_node);
    return value;
}


static const char *api_read_value_depth_2(int cmd, int cmd_2)
{
    static char value[HID_REPORT_SIZE];
    memset(value, 0, sizeof(value));

    yajl_val json_node = yajl_tree_parse(api_read_decrypted_report(), NULL, 0);
    if (json_node && YAJL_IS_OBJECT(json_node)) {
        const char *path[] = { cmd_str(cmd), cmd_str(cmd_2), NULL };
        const char *v = YAJL_GET_STRING(yajl_tree_get(json_node, path, yajl_t_string));
        snprintf(value, sizeof(value), "%s", v);
    }

    yajl_tree_free(json_node);
    return value;
}


static const char *api_read_array_value(int cmd, int cmd_2, int index)
{
    const char *path[] = { cmd_str(cmd), NULL };
    const char *a_path[] = { cmd_str(cmd_2), NULL };
    static char value[HID_REPORT_SIZE];
    memset(value, 0, sizeof(value));

    yajl_val json_node = yajl_tree_parse(api_read_decrypted_report(), NULL, 0);
    if (json_node && YAJL_IS_OBJECT(json_node)) {
        yajl_val data = yajl_tree_get(json_node, path, yajl_t_array);
        if (YAJL_IS_ARRAY(data) && data->u.array.len != 0) {
            yajl_val obj = data->u.array.values[index];
            const char *a = YAJL_GET_STRING(yajl_tree_get(obj, a_path, yajl_t_string));
            if (a) {
                snprintf(value, sizeof(value), "%s", a);
            }
        }
    }

    yajl_tree_free(json_node);
    return value;
}


static char *api_read_value_decrypt(int cmd, uint8_t *key)
{
    const char *val = api_read_value(cmd);
    static char val_dec[HID_REPORT_SIZE];
    memset(val_dec, 0, sizeof(val_dec));

    int decrypt_len;
    char *dec = cipher_aes_b64_decrypt((const unsigned char *)val, strlens(val),
                                       &decrypt_len, key);

    snprintf(val_dec, HID_REPORT_SIZE, "%.*s", decrypt_len, dec);
    free(dec);
    return val_dec;
}

#endif

