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


#ifndef _API_H_
#define _API_H_


#include "utils.h"
#include "flags.h"
#include "commander.h"


#define HID_REPORT_SIZE   COMMANDER_REPORT_SIZE


static const char tests_pwd[] = "0000";
static char command_sent[COMMANDER_REPORT_SIZE] = {0};
static int TEST_LIVE_DEVICE = 0;


#ifndef CONTINUOUS_INTEGRATION
// http://www.signal11.us/oss/hidapi/
#include <hidapi.h>

static hid_device *HID_HANDLE;
static unsigned char HID_REPORT[HID_REPORT_SIZE] = {0};

static int api_hid_init(void)
{
    HID_HANDLE = hid_open(0x03eb, 0x2402, NULL);
    if (!HID_HANDLE) {
        return DBB_ERROR;
    }
    return DBB_OK;
}


static void api_hid_read(void)
{
    int res, cnt = 0;
    memset(HID_REPORT, 0, HID_REPORT_SIZE);
    while (cnt < HID_REPORT_SIZE) {
        res = hid_read(HID_HANDLE, HID_REPORT + cnt, HID_REPORT_SIZE);
        if (res < 0) {
            printf("ERROR: Unable to read report.\n");
            return;
        }
        cnt += res;
    }
    utils_decrypt_report((char *)HID_REPORT);
    //printf("received:  >>%s<<\n", utils_read_decrypted_report());
}


static void api_hid_send_len(const char *cmd, int cmdlen)
{
    memset(HID_REPORT, 0, HID_REPORT_SIZE);
    memcpy(HID_REPORT, cmd, cmdlen );
    hid_write(HID_HANDLE, (unsigned char *)HID_REPORT, HID_REPORT_SIZE);
}


static void api_hid_send(const char *cmd)
{
    api_hid_send_len(cmd, strlens(cmd));
}


static void api_hid_send_encrypt(const char *cmd)
{
    int enc_len;
    char *enc = aes_cbc_b64_encrypt((const unsigned char *)cmd, strlens(cmd), &enc_len,
                                    PASSWORD_STAND);
    api_hid_send_len(enc, enc_len);
    free(enc);
}
#endif


static void api_send_cmd(const char *command, PASSWORD_ID id)
{
    memset(command_sent, 0, sizeof(command_sent));
    if (command) {
        memcpy(command_sent, command, strlens(command));
    }
    if (!TEST_LIVE_DEVICE) {
        utils_send_cmd(command, id);
    }
#ifndef CONTINUOUS_INTEGRATION
    else if (id == PASSWORD_NONE) {
        api_hid_send(command);
        api_hid_read();
    } else {
        api_hid_send_encrypt(command);
        api_hid_read();
    }
#endif
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
    api_format_send_cmd(cmd_str(CMD_password), tests_pwd,
                        PASSWORD_NONE);// in case not yet set
    api_format_send_cmd(cmd_str(CMD_reset), attr_str(ATTR___ERASE__), PASSWORD_STAND);
}


static const char *api_read_value(int cmd)
{
    static char value[HID_REPORT_SIZE];
    memset(value, 0, sizeof(value));

    yajl_val json_node = yajl_tree_parse(utils_read_decrypted_report(), NULL, 0);
    if (json_node && YAJL_IS_OBJECT(json_node)) {
        const char *path[] = { cmd_str(cmd), NULL };
        yajl_val v = yajl_tree_get(json_node, path, yajl_t_string);
        snprintf(value, sizeof(value), "%s", v->u.string);
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

