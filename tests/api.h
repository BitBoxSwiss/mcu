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


#ifndef _API_H_
#define _API_H_


#include <arpa/inet.h>
#include "flags.h"
#include "yajl/src/api/yajl_tree.h"
#include "u2f/u2f_hid.h"
#include "u2f/u2f.h"
#include "u2f_device.h"
#include "usb.h"


#define HWW_CID 0xff000000
#define HID_REPORT_SIZE   COMMANDER_REPORT_SIZE


#ifndef CONTINUOUS_INTEGRATION
// http://www.signal11.us/oss/hidapi/
#include <hidapi.h>

static hid_device *HID_HANDLE;
#endif


static const char tests_pwd[] = "0000";
static const char hidden_pwd[] = "hide";
static char command_sent[COMMANDER_REPORT_SIZE] = {0};
static int TEST_LIVE_DEVICE = 0;

static unsigned char HID_REPORT[HID_REPORT_SIZE] = {0};
static char decrypted_report[COMMANDER_REPORT_SIZE];


static const char *api_read_decrypted_report(void)
{
    return decrypted_report;
}


static void api_decrypt_report(const char *report, PASSWORD_ID dec_id)
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
        const char *echo_path[] = { "echo", (const char *) 0 };
        const char *ciphertext = YAJL_GET_STRING(yajl_tree_get(json_node, ciphertext_path,
                                 yajl_t_string));
        const char *echo = YAJL_GET_STRING(yajl_tree_get(json_node, echo_path, yajl_t_string));
        if (ciphertext) {
            dec = aes_cbc_b64_decrypt((const unsigned char *)ciphertext, strlens(ciphertext),
                                      &decrypt_len, dec_id);
            if (!dec) {
                strcpy(decrypted_report, "/* error: Failed to decrypt. */");
                goto exit;
            }

            sprintf(decrypted_report, "/* ciphertext */ %.*s", decrypt_len, dec);
            free(dec);
            goto exit;
        } else if (echo) {
            dec = aes_cbc_b64_decrypt((const unsigned char *)echo, strlens(echo), &decrypt_len,
                                      PASSWORD_VERIFY);
            if (!dec) {
                strcpy(decrypted_report, "/* error: Failed to decrypt echo. */");
                goto exit;
            }

            sprintf(decrypted_report, "/* echo */ %.*s", decrypt_len, dec);
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
                      size - COMMANDER_REPORT_SIZE);
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


static void api_hid_read(PASSWORD_ID id)
{
    memset(HID_REPORT, 0, HID_REPORT_SIZE);
    int res = api_hid_read_frames(HWW_CID, U2FHID_HWW, HID_REPORT, HID_REPORT_SIZE);
    if (res < 0) {
        printf("ERROR: Unable to read report.\n");
        return;
    }
    api_decrypt_report((char *)HID_REPORT, id);
    //printf("received:  >>%s<<\n", api_read_decrypted_report());
}


static void api_hid_send_len(const char *cmd, int cmdlen)
{
    api_hid_send_frames(HWW_CID, U2FHID_HWW, cmd, cmdlen);
}


static void api_hid_send(const char *cmd)
{
    api_hid_send_len(cmd, strlens(cmd));
}


static void api_hid_send_encrypt(const char *cmd, PASSWORD_ID id)
{
    int enc_len;
    char *enc = aes_cbc_b64_encrypt((const unsigned char *)cmd, strlens(cmd), &enc_len, id);
    api_hid_send_len(enc, enc_len);
    free(enc);
}


static void api_send_cmd(const char *command, PASSWORD_ID id)
{
    memset(command_sent, 0, sizeof(command_sent));
    if (command) {
        memcpy(command_sent, command, strlens(command));
    }
    if (id == PASSWORD_NONE) {
        api_hid_send(command);
        api_hid_read(id);
    } else {
        api_hid_send_encrypt(command, id);
        api_hid_read(id);
    }
}


static void api_format_send_cmd(const char *cmd, const char *val, PASSWORD_ID id)
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
    api_send_cmd(command, id);
}


static void api_reset_device(void)
{
    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE); // if not set
    api_format_send_cmd(cmd_str(CMD_reset), attr_str(ATTR___ERASE__), PASSWORD_STAND);
}


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


static char *api_read_value_decrypt(int cmd, PASSWORD_ID id)
{
    const char *val = api_read_value(cmd);
    static char val_dec[HID_REPORT_SIZE];
    memset(val_dec, 0, sizeof(val_dec));

    int decrypt_len;
    char *dec = aes_cbc_b64_decrypt((const unsigned char *)val, strlens(val),
                                    &decrypt_len, id);

    snprintf(val_dec, HID_REPORT_SIZE, "%.*s", decrypt_len, dec);
    free(dec);
    return val_dec;
}

#endif

