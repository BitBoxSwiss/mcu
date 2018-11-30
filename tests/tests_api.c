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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sd.h"
#include "ecdh.h"
#include "ecc.h"
#include "sha2.h"
#include "bip32.h"
#include "utest.h"
#include "utils.h"
#include "flags.h"
#include "random.h"
#include "cipher.h"
#include "commander.h"
#include "yajl/src/api/yajl_tree.h"
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_recovery.h"

#include "api.h"
#include "version.h"


#define HASH_DEFAULT       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define HASH_INPUT_ONE     "c6fa4c236f59020ec8ffde22f85a78e7f256e94cd975eb5199a4a5cc73e26e4a"
#define HASH_INPUT_TWO_1   "c12d791451bb41fd4b5145bcef25f794ca33c0cf4fe9d24f956086c5aa858a9d"
#define HASH_INPUT_TWO_2   "3dfc3b1ed349e9b361b31c706fbf055ebf46ae725740f6739e2dfa87d2a98790"
#define KEYPATH_BASE       "m/44p"
#define KEYPATH_ONE        "m/44'/0'/0'/1/7"
#define KEYPATH_TWO        "m/44'/0'/0'/1/8"
#define KEYPATH_THREE      "m/44'/0'/0'/0/5"
#define PUBKEY_INPUT_ONE   "025acc8c55e1a786f7b8ca742f725909019c849abe2051b7bc8bc580af3dc17154"
#define PUBKEY_INPUT_TWO_1 "035e8c69793fd853795759b8ca12229d7b2e7ec2223221dc224885fc9a1e7e1704"
#define PUBKEY_INPUT_TWO_2 "03cc673784d8dfe97ded72c91ebb1b87a52761e4be20f6229e56fd61fdf28ae3f2"
#define PUBKEY_ZERO        "000000000000000000000000000000000000000000000000000000000000000000"
#define RECID_01           "01"
#define RECID_EE           "ee"


int U_TESTS_RUN = 0;
int U_TESTS_FAIL = 0;


static void tests_seed_xpub_backup(void)
{
    char name0[] = "name0";
    char key[] = "password";
    char xpub0[112], xpub1[112];
    char seed_usb[512], seed_c[512], seed_b[512], back[512], check[512], erase_file[512];
    char filename[] = "tests_backup.pdf";
    char filename2[] = "tests_backup2.pdf";
    char filename_create[] = "tests_backup_c.pdf";
    char filename_bad[] = "tests_backup_bad<.pdf";
    char keypath[] = "m/44\'/0\'/";
    char seed_create[] =
        "{\"source\":\"create\", \"filename\":\"seed_create.pdf\", \"key\":\"password\"}";
    char seed_create_2[] =
        "{\"source\":\"create\", \"filename\":\"seed_create_2.pdf\", \"key\":\"password\"}";
    char seed_create_bad[] =
        "{\"source\":\"create\", \"filename\":\"../seed_create_bad.pdf\", \"key\":\"password\"}";
    char seed_entropy[] = "entropy_><?.$#`}0123456789abcdef0123456789abcdef0123456789abcdef";
    char seed_entropy_short[] = "entropy_tooshort";
    char seed_entropy_long[] =
        "entropy_><?.$#`0123456789abcdef0123456789abcdef0123456789abcdef_toolong";

    snprintf(seed_c, sizeof(seed_c),
             "{\"source\":\"%s\", \"filename\":\"%s\", \"key\":\"%s\"}", attr_str(ATTR_create),
             filename_create, key);
    snprintf(seed_b, sizeof(seed_b),
             "{\"source\":\"backup\",\"filename\":\"%s\",\"key\":\"%s\"}", filename, key);
    snprintf(back, sizeof(back), "{\"filename\":\"%s\",\"key\":\"%s\"}", filename, key);
    snprintf(check, sizeof(check), "{\"check\":\"%s\",\"key\":\"%s\"}", filename, key);
    snprintf(seed_usb, sizeof(seed_usb),
             "{\"source\":\"create\",\"entropy\":\"%s\",\"filename\":\"%s\",\"key\":\"%s\"}",
             seed_entropy, filename, key);


    // erase
    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_SUCCESS;

    // rename
    api_format_send_cmd(cmd_str(CMD_name), name0, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    u_assert_str_eq(name0, api_read_value(CMD_name));

    memset(xpub0, 0, sizeof(xpub0));
    memset(xpub1, 0, sizeof(xpub1));

    api_format_send_cmd(cmd_str(CMD_backup), back, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_MASTER));

    // create
    api_format_send_cmd(cmd_str(CMD_xpub), keypath, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_seed), seed_c, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_xpub), keypath, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    memcpy(xpub0, api_read_value(CMD_xpub), sizeof(xpub0));
    u_assert_str_not_eq(xpub0, xpub1);

    if (!TEST_LIVE_DEVICE) {
        int len;
        const char *val = api_read_value(CMD_echo);
        char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                     memory_report_aeskey(TFA_SHARED_SECRET));
        u_assert(echo);
        u_assert_str_eq(xpub0, echo);
        free(echo);
    }

    // check backup list and erase
    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), KEY_STANDARD);
    ASSERT_REPORT_HAS(filename_create);

    // backup
    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), KEY_STANDARD);
    ASSERT_SUCCESS;
    ASSERT_REPORT_HAS_NOT(filename_create);
    ASSERT_REPORT_HAS_NOT(flag_msg(DBB_ERR_SD_ERASE));

    api_format_send_cmd(cmd_str(CMD_backup), back, KEY_STANDARD);
    ASSERT_SUCCESS;

    // erase device
    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_SUCCESS;

    // check has default name
    api_format_send_cmd(cmd_str(CMD_name), "", KEY_STANDARD);
    u_assert_str_eq(DEVICE_DEFAULT_NAME, api_read_value(CMD_name));

    // load backup
    api_format_send_cmd(cmd_str(CMD_seed), seed_b, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_name), "", KEY_STANDARD);
    u_assert_str_eq(name0, api_read_value(CMD_name));

    api_format_send_cmd(cmd_str(CMD_xpub), keypath, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    memcpy(xpub1, api_read_value(CMD_xpub), sizeof(xpub1));
    if (!TEST_LIVE_DEVICE) {
        int len;
        const char *val = api_read_value(CMD_echo);
        char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                     memory_report_aeskey(TFA_SHARED_SECRET));
        u_assert(echo);
        u_assert_str_eq(xpub0, echo);
        free(echo);
    }

    // check xpubs
    u_assert_str_eq(xpub0, xpub1);

    // check backup list and erase
    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), KEY_STANDARD);
    ASSERT_REPORT_HAS(filename);
    ASSERT_REPORT_HAS_NOT(filename_create);

    api_format_send_cmd(cmd_str(CMD_backup), check, KEY_STANDARD);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), KEY_STANDARD);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(filename);
    ASSERT_REPORT_HAS_NOT(filename_create);

    api_format_send_cmd(cmd_str(CMD_backup), check, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_READ_FILE));


    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), KEY_STANDARD);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_seed), seed_create, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), KEY_STANDARD);
    ASSERT_REPORT_HAS("seed_create.pdf");

    api_format_send_cmd(cmd_str(CMD_seed), seed_create_bad, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_BAD_CHAR));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT("../seed_create_bad.pdf");

    // test sd list overflow
    char long_backup_name[SD_FILEBUF_LEN_MAX / 8];
    char lbn[SD_FILEBUF_LEN_MAX / 8];
    size_t i;

    memset(long_backup_name, '-', sizeof(long_backup_name) - 1);
    long_backup_name[(SD_FILEBUF_LEN_MAX / 8) - 1] = 0;

    for (i = 0; i < SD_FILEBUF_LEN_MAX / sizeof(long_backup_name); i++) {
        snprintf(lbn, sizeof(lbn), "%lu%s", (unsigned long)i, long_backup_name);
        snprintf(back, sizeof(back), "{\"filename\":\"%s\", \"key\":\"password\"}", lbn);
        api_format_send_cmd(cmd_str(CMD_backup), back, KEY_STANDARD);
        ASSERT_SUCCESS;

        api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), KEY_STANDARD);
        ASSERT_REPORT_HAS_NOT(cmd_str(CMD_warning));
    }

    snprintf(lbn, sizeof(lbn), "%lu%s", (unsigned long)i, long_backup_name);
    snprintf(back, sizeof(back), "{\"filename\":\"%s\", \"key\":\"password\"}", lbn);
    api_format_send_cmd(cmd_str(CMD_backup), back, KEY_STANDARD);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_warning));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), KEY_STANDARD);
    ASSERT_SUCCESS;

    // test keypath
    api_format_send_cmd(cmd_str(CMD_xpub), "m/111'", KEY_STANDARD);
    ASSERT_REPORT_HAS("\"xpub\":");
    api_format_send_cmd(cmd_str(CMD_xpub), "m/1/2'/3/4", KEY_STANDARD);
    ASSERT_REPORT_HAS("\"xpub\":");

    api_format_send_cmd(cmd_str(CMD_xpub), "m/1/2/3", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "111", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "/111", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "m", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "m111", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/a", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/!", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/-111", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/'0", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/'", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "m//", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/ ", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_CHILD));



    // test create seeds differ
    memset(xpub0, 0, sizeof(xpub0));
    memset(xpub1, 0, sizeof(xpub1));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/0'", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    memcpy(xpub0, api_read_value(CMD_xpub), sizeof(xpub0));
    u_assert_str_not_eq(xpub0, xpub1);

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(filename);

    snprintf(back, sizeof(back), "{\"filename\":\"%s\", \"key\":\"password\"}", filename_bad);
    api_format_send_cmd(cmd_str(CMD_backup), back, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_BAD_CHAR));

    snprintf(check, sizeof(check), "{\"check\":\"%s\", \"key\":\"password\"}", filename_bad);
    api_format_send_cmd(cmd_str(CMD_backup), check, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_BAD_CHAR));

    snprintf(back, sizeof(back), "{\"filename\":\"%s\", \"key\":\"password\"}", filename);
    api_format_send_cmd(cmd_str(CMD_backup), back, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(check, sizeof(check), "{\"check\":\"%s\", \"key\":\"password\"}", filename);
    api_format_send_cmd(cmd_str(CMD_backup), check, KEY_STANDARD);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_seed), seed_create_2, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/0'", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    memcpy(xpub1, api_read_value(CMD_xpub), sizeof(xpub0));
    u_assert_str_not_eq(xpub0, xpub1);

    api_format_send_cmd(cmd_str(CMD_backup), check, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

    // test cannot overwrite existing backup file
    api_format_send_cmd(cmd_str(CMD_seed), seed_create_2, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_OPEN_FILE));

    // test erase single backup file
    if (!TEST_LIVE_DEVICE) {
        // testing buffer gets overwritten by seed command, so reset it
        api_format_send_cmd(cmd_str(CMD_backup), back, KEY_STANDARD);
        ASSERT_SUCCESS;
    }

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), KEY_STANDARD);
    ASSERT_REPORT_HAS(filename);

    snprintf(erase_file, sizeof(erase_file), "{\"%s\":\"%s\"}", attr_str(ATTR_erase),
             filename);

    api_format_send_cmd(cmd_str(CMD_backup), erase_file, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(erase_file, sizeof(erase_file), "{\"%s\":\"%s\"}", attr_str(ATTR_erase),
             filename_bad);
    api_format_send_cmd(cmd_str(CMD_backup), erase_file, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_BAD_CHAR));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(filename);


    // test seed via USB
    memset(xpub0, 0, sizeof(xpub0));
    memset(xpub1, 0, sizeof(xpub1));

    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), KEY_STANDARD);
    ASSERT_SUCCESS;

    // seed with extra entropy from device
    api_format_send_cmd(cmd_str(CMD_seed), seed_usb, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/0'", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    memcpy(xpub0, api_read_value(CMD_xpub), sizeof(xpub0));
    u_assert_str_not_eq(xpub0, xpub1);

    // seed with extra entropy from device (entropy too short)
    snprintf(seed_usb, sizeof(seed_usb),
             "{\"source\":\"create\",\"entropy\":\"%s\",\"filename\":\"%s\",\"key\":\"%s\"}",
             seed_entropy_short, filename2, key);
    api_format_send_cmd(cmd_str(CMD_seed), seed_usb, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    // seed with extra entropy from device (entropy too long)
    snprintf(seed_usb, sizeof(seed_usb),
             "{\"source\":\"create\",\"entropy\":\"%s\",\"filename\":\"%s\",\"key\":\"%s\"}",
             seed_entropy_long, filename2, key);
    api_format_send_cmd(cmd_str(CMD_seed), seed_usb, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    // seed with extra entropy from device
    snprintf(seed_usb, sizeof(seed_usb),
             "{\"source\":\"create\",\"entropy\":\"%s\",\"filename\":\"%s\",\"key\":\"%s\"}",
             seed_entropy, filename2, key);
    api_format_send_cmd(cmd_str(CMD_seed), seed_usb, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    // verify xpubs not same
    api_format_send_cmd(cmd_str(CMD_xpub), "m/0'", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    memcpy(xpub1, api_read_value(CMD_xpub), sizeof(xpub1));
    u_assert_str_not_eq(xpub0, xpub1);

    // load backup
    api_format_send_cmd(cmd_str(CMD_seed), seed_b, KEY_STANDARD);
    ASSERT_SUCCESS;

    // verify xpub matches
    api_format_send_cmd(cmd_str(CMD_xpub), "m/0'", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    memcpy(xpub1, api_read_value(CMD_xpub), sizeof(xpub1));
    u_assert_str_eq(xpub0, xpub1);


    // clean up sd card
    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), KEY_STANDARD);
    ASSERT_SUCCESS;
}


static void tests_random(void)
{
    char number0[32 + 1] = {0};
    char number1[32 + 1] = {0};

    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_random), attr_str(ATTR_pseudo), KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));

    memcpy(number0, api_read_value(CMD_random), sizeof(number0));

    api_format_send_cmd(cmd_str(CMD_random), attr_str(ATTR_pseudo), KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    memcpy(number1, api_read_value(CMD_random), sizeof(number1));
    u_assert_str_not_eq(number0, number1);

    api_format_send_cmd(cmd_str(CMD_random), attr_str(ATTR_true), KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    memcpy(number0, api_read_value(CMD_random), sizeof(number0));

    api_format_send_cmd(cmd_str(CMD_random), attr_str(ATTR_true), KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    memcpy(number1, api_read_value(CMD_random), sizeof(number1));
    u_assert_str_not_eq(number0, number1);

    api_format_send_cmd(cmd_str(CMD_random), "invalid_cmd", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));
}


static void tests_name(void)
{
    char name0[] = "name0";
    char name1[] = "name1";

    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_name), name0, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    u_assert_str_eq(name0, api_read_value(CMD_name));

    api_format_send_cmd(cmd_str(CMD_name), name1, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    u_assert_str_eq(name1, api_read_value(CMD_name));

    api_format_send_cmd(cmd_str(CMD_name), "", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    u_assert_str_eq(name1, api_read_value(CMD_name));
}


static void tests_u2f(void)
{
    USB_FRAME f, r;
    uint32_t cid = 5;
    int test_u2fauth_hijack = TEST_U2FAUTH_HIJACK;
    api_create_u2f_frame(&f, cid, U2FHID_WINK, 0, NULL);

    api_reset_device();

    // U2F command should run on fresh device
    api_hid_send_frame(&f);
    api_hid_read_frame(&r);
    u_assert_int_eq(r.cid, cid);
    u_assert_int_eq(r.init.cmd, U2FHID_WINK);
    u_assert_int_eq(r.init.bcntl, 0);

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), KEY_STANDARD);
    ASSERT_SUCCESS;

    // Seed
    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_info), KEY_STANDARD);
    ASSERT_REPORT_HAS("\"U2F\":true");
    ASSERT_REPORT_HAS("\"U2F_hijack\":true");

    api_format_send_cmd(cmd_str(CMD_seed),
                        "{\"source\":\"create\", \"filename\":\"u2f_test_0.pdf\", \"key\":\"password\"}",
                        KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    // U2F command runs
    api_hid_send_frame(&f);
    api_hid_read_frame(&r);
    u_assert_int_eq(r.cid, cid);
    u_assert_int_eq(r.init.cmd, U2FHID_WINK);
    u_assert_int_eq(r.init.bcntl, 0);

    // Disable U2F
    api_format_send_cmd(cmd_str(CMD_feature_set), "{\"U2F\":false}", KEY_STANDARD);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_info), KEY_STANDARD);
    if (TEST_U2FAUTH_HIJACK) {
        ASSERT_REPORT_HAS(API_READ_ERROR);
    } else {
        ASSERT_REPORT_HAS("\"U2F\":false");
        ASSERT_REPORT_HAS("\"U2F_hijack\":true");
    }

    // U2F command should abort
    api_hid_send_frame(&f);
    api_hid_read_frame(&r);
    u_assert_int_eq(r.cid, cid);
    u_assert_int_eq(r.init.cmd, U2FHID_ERROR);
    u_assert_int_eq(r.init.bcntl, 1);
    u_assert_int_eq(r.init.data[0], U2FHID_ERR_CHANNEL_BUSY);

    // Enable U2F - Must be done through HWW interface.
    TEST_U2FAUTH_HIJACK = 0;
    api_format_send_cmd(cmd_str(CMD_feature_set), "{\"U2F\":true}", KEY_STANDARD);
    ASSERT_SUCCESS;
    TEST_U2FAUTH_HIJACK = test_u2fauth_hijack;

    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_info), KEY_STANDARD);
    ASSERT_REPORT_HAS("\"U2F\":true");
    ASSERT_REPORT_HAS("\"U2F_hijack\":true");


    // Disable U2F hijack
    api_format_send_cmd(cmd_str(CMD_feature_set), "{\"U2F_hijack\":false}", KEY_STANDARD);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_info), KEY_STANDARD);
    if (TEST_U2FAUTH_HIJACK) {
        ASSERT_REPORT_HAS(API_READ_ERROR);
    } else {
        ASSERT_REPORT_HAS("\"U2F\":true");
        ASSERT_REPORT_HAS("\"U2F_hijack\":false");
    }

    // U2F command runs
    api_hid_send_frame(&f);
    api_hid_read_frame(&r);
    u_assert_int_eq(r.cid, cid);
    u_assert_int_eq(r.init.cmd, U2FHID_WINK);
    u_assert_int_eq(r.init.bcntl, 0);

    // Enable U2F hijack - Must be done through HWW interface.
    TEST_U2FAUTH_HIJACK = 0;
    api_format_send_cmd(cmd_str(CMD_feature_set), "{\"U2F_hijack\":true}", KEY_STANDARD);
    ASSERT_SUCCESS;
    TEST_U2FAUTH_HIJACK = test_u2fauth_hijack;

    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_info), KEY_STANDARD);
    ASSERT_REPORT_HAS("\"U2F\":true");
    ASSERT_REPORT_HAS("\"U2F_hijack\":true");

    // Send invalid commands
    api_format_send_cmd(cmd_str(CMD_feature_set), "{}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_feature_set), "{\"Foo\":false}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_feature_set), "{\"U2F\":\"false\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_info), KEY_STANDARD);
    ASSERT_REPORT_HAS("\"U2F\":true");

    api_format_send_cmd(cmd_str(CMD_feature_set), "{\"U2F\":\"true\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));


    //
    // U2F counter updating tested in tests_u2f_standard.c
    //


    //
    // U2F backup and recovery
    //
    char cmd[512];
    char fn0[] = "u2ftest0.pdf";
    char fn1[] = "u2ftest1.pdf";
    char fn2[] = "u2ftest2.pdf";
    char fn2c[] = "u2ftest2c.pdf";
    char fn3[] = "u2ftest3.pdf";
    char fn3h[] = "u2ftest3h.pdf";
    char fn3u[] = "u2ftest3u.pdf";
    char fn3a[] = "u2ftest3a.pdf";
    char fn4[] = "u2ftest4.pdf";


    // reset device
    // set password
    // erase sd
    // reset u2f fail (would create backup `all` by default but cannot because not seeded)
    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"%s\", \"key\":\"password\", \"filename\":\"%s\", \"U2F_counter\":100}",
             attr_str(ATTR_U2F_create), fn0);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_MASTER));


    // seed0 (creates backup0 `all` by default)
    // verify backup0 `u2f` success
    // verify backup0 `hww` success
    // verify backup0 ``    success (default hww)
    // verify backup0 `all` success (invalid cmd)
    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"create\", \"filename\":\"%s\", \"key\":\"password\"}", fn0);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn0,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn0, attr_str(ATTR_HWW));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\"}", fn0);
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"\"}",
             fn0);
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn0, attr_str(ATTR_all));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    // verify error on invalid `source` command
    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn0, "badcmd");
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));


    // seed1 (creates backup1 `all` by default)
    // verify backup0 `u2f` success
    // verify backup0 `hww` fail
    // verify backup0 ``    fail
    // verify backup1 `u2f` success
    // verify backup1 `hww` success
    // verify backup1 ``    success
    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"create\", \"filename\":\"%s\", \"key\":\"password\"}", fn1);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn0,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn0, attr_str(ATTR_HWW));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\"}", fn0);
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn1,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn1, attr_str(ATTR_HWW));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\"}", fn1);
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;


    // reset u2f (creates backup2 `all` by default)
    // reset with invalid command (aborts reset)
    // verify backup1 `u2f` fail
    // verify backup2 `u2f` success

    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"%s\", \"key\":\"password\", \"filename\":\"%s\", \"U2F_counter\":100}",
             attr_str(ATTR_U2F_create), fn2c);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"%s\", \"filename\":\"%s\", \"U2F_counter\":100}",
             attr_str(ATTR_U2F_create), fn2c);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_KEY));

    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"%s\", \"key\":\"password\", \"U2F_counter\":100}",
             attr_str(ATTR_U2F_create));
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn1,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn2c,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    // repeat reset u2f without counter field
    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"%s\", \"key\":\"password\", \"filename\":\"%s\"}",
             attr_str(ATTR_U2F_create), fn2);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn2c,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn2,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;


    // create backup3 (no source specified -> `all` by default)
    // create backup3h `hww`
    // create backup3u `u2f`
    // create backup3a `all`
    snprintf(cmd, sizeof(cmd), "{\"filename\":\"%s\",\"key\":\"password\"}", fn3);
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"filename\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn3h, attr_str(ATTR_HWW));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"filename\":\"%s\",\"source\":\"%s\"}", fn3u,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"filename\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn3a, attr_str(ATTR_all));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;



    // verify backup0 `u2f` fail
    // verify backup0 `hww` fail
    // verify backup0 `all` fail
    // verify backup0 ``    fail
    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn0,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn0, attr_str(ATTR_HWW));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn0, attr_str(ATTR_all));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\"}", fn0);
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));


    // verify backup2 `u2f` success
    // verify backup2 `hww` success
    // verify backup2 ``    success (default hww)
    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn2,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn2, attr_str(ATTR_HWW));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\"}", fn2);
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;


    // verify backup3 `u2f` success
    // verify backup3 `hww` success
    // verify backup3 ``    success (default hww)
    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn3,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn3, attr_str(ATTR_HWW));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\"}", fn3);
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;


    // verify backup3h `u2f` fail
    // verify backup3h `hww` success
    // verify backup3h `all` fail
    // verify backup3h ``    success (default hww)
    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn3h,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn3h, attr_str(ATTR_HWW));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn3h, attr_str(ATTR_all));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\"}", fn3h);
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;


    // verify backup3u `u2f` success
    // verify backup3u `hww` fail
    // verify backup3u ``    fail (default hww)
    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn3u,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn3u, attr_str(ATTR_HWW));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\"}", fn3u);
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));


    // verify backup3a `u2f` success
    // verify backup3a `hww` success
    // verify backup3a ``    success (default hww)
    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn3a,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn3a, attr_str(ATTR_HWW));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\"}", fn3a);
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;


    // recover backup0 u2f
    // recover backup3u hww fail
    // recover backup3u all fail (invalid cmd)
    snprintf(cmd, sizeof(cmd), "{\"source\":\"%s\", \"filename\":\"%s\"}",
             attr_str(ATTR_U2F_load), fn0);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"%s\", \"filename\":\"%s\", \"key\":\"password\"}", attr_str(ATTR_backup),
             fn3u);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SEED_INVALID));

    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"%s\", \"filename\":\"%s\", \"key\":\"password\"}", attr_str(ATTR_all),
             fn3u);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));


    // verify backup3u `u2f` fail
    // verify backup0 `u2f` success
    // verify backup0 `hww` fail
    // verify backup0 ``    fail (default hww)
    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn3u,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn0,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn0, attr_str(ATTR_HWW));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\"}", fn0);
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));


    // recover backup3u u2f success [with counter set]
    // verify backup3u `u2f` success
    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"%s\", \"filename\":\"%s\", \"U2F_counter\":100}", attr_str(ATTR_U2F_load),
             fn3u);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn3u,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;


    // recover backup0 hww
    // recover backup3h u2f fail
    // recover backup3h all fail (invalid cmd)
    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"%s\", \"filename\":\"%s\", \"key\":\"password\"}", attr_str(ATTR_backup),
             fn0);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"%s\", \"filename\":\"%s\", \"key\":\"password\"}", attr_str(ATTR_U2F_load),
             fn3h);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SEED_INVALID));

    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"%s\", \"filename\":\"%s\", \"key\":\"password\"}", attr_str(ATTR_all),
             fn3h);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));


    // verify backup3h `hww` fail
    // verify backup0 `u2f` fail
    // verify backup0 `hww` success
    // verify backup0 `all` fail
    // verify backup0 ``    success
    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn3h, attr_str(ATTR_HWW));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn0,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn0, attr_str(ATTR_HWW));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn0, attr_str(ATTR_all));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\"}", fn0);
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;


    // verify backup3u `u2f` success
    // verify backup0  `hww` success
    // reset u2f (fail; deprecated cmd)
    // reset u2f (creates backup4 `all` by default)
    // verify backup3u `u2f` fail
    // verify backup4u `u2f` success
    // verify backup0  `hww` success
    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn3u,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn0, attr_str(ATTR_HWW));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"%s\", \"key\":\"password\", \"filename\":\"%s\"}",
             attr_str(ATTR_U2F_create), fn4);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_reset), attr_str(ATTR_U2F), KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn3u,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn4,
             attr_str(ATTR_U2F));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;

    snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"password\",\"source\":\"%s\"}",
             fn0, attr_str(ATTR_HWW));
    api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;


    //
    // u2f sample sd files
    //
    if (!TEST_LIVE_DEVICE) {

        const char one_input[] =
            "{\"data\":[{\"hash\":\"" HASH_INPUT_ONE "\", \"keypath\":\"" KEYPATH_ONE "\"}]}";
        const char sig_1_input[] =
            "61e87a12a111987e3bef9dffd4b30a0322f2cc74e65a19aa551a3eaa8f417d0b18305a52f94153980f6e6d4383decc68028764b4f60ecb0d2a28e74359073012";
        const char tb_v2_3a[] = "test_backup.pdf";
        const char tb_v2_3h[] = "test_backup_hww.pdf";
        const char tb_v2_3u[] = "test_backup_u2f.pdf";
        const char tb_v2_2[] = "test_backup_v2.2.3.pdf";// backward compatability test


        // copy test sd_files to sd card directory
        int ret = system("cp ../tests/sd_files/*.pdf tests/digitalbitbox/");
        u_assert(ret == 0);

        // verify  v23a u2f fail
        // verify  v23a hww fail
        snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", tb_v2_3a,
                 attr_str(ATTR_U2F));
        api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
        ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

        snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"key\",\"source\":\"%s\"}",
                 tb_v2_3a, attr_str(ATTR_HWW));
        api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
        ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));


        // recover v23u u2f success
        // recover v23u hww fail
        // verify  v23u u2f success
        // verify  v23u hww fail
        // sign             fail
        snprintf(cmd, sizeof(cmd), "{\"source\":\"%s\", \"filename\":\"%s\"}",
                 attr_str(ATTR_U2F_load), tb_v2_3u);
        api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        snprintf(cmd, sizeof(cmd), "{\"source\":\"%s\", \"filename\":\"%s\", \"key\":\"key\"}",
                 attr_str(ATTR_backup), tb_v2_3u);
        api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
        ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SEED_INVALID));

        snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", tb_v2_3u,
                 attr_str(ATTR_U2F));
        api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"key\",\"source\":\"%s\"}",
                 tb_v2_3u, attr_str(ATTR_HWW));
        api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
        ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_NO_MATCH));

        api_format_send_cmd(cmd_str(CMD_sign), one_input, KEY_STANDARD);
        ASSERT_REPORT_HAS(cmd_str(CMD_echo));
        if (!TEST_LIVE_DEVICE) {
            int len;
            const char *val = api_read_value(CMD_echo);
            char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                         memory_report_aeskey(TFA_SHARED_SECRET));
            u_assert(echo);
            u_assert_str_has(echo, KEYPATH_ONE);
            free(echo);
        }
        api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
        ASSERT_REPORT_HAS_NOT(sig_1_input);


        // recover fn4  u2f success
        // recover v23h hww success
        // recover v23h u2f fail
        // verify  fn4  u2f success
        // verify  v23h hww success
        // sign             success
        snprintf(cmd, sizeof(cmd), "{\"source\":\"%s\", \"filename\":\"%s\"}",
                 attr_str(ATTR_U2F_load), fn4);
        api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        snprintf(cmd, sizeof(cmd), "{\"source\":\"%s\", \"filename\":\"%s\", \"key\":\"key\"}",
                 attr_str(ATTR_backup), tb_v2_3h);
        api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        snprintf(cmd, sizeof(cmd), "{\"source\":\"%s\", \"filename\":\"%s\"}",
                 attr_str(ATTR_U2F_load), tb_v2_3h);
        api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
        ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SEED_INVALID));

        snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", fn4,
                 attr_str(ATTR_U2F));
        api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"key\",\"source\":\"%s\"}",
                 tb_v2_3h, attr_str(ATTR_HWW));
        api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        api_format_send_cmd(cmd_str(CMD_sign), one_input, KEY_STANDARD);
        ASSERT_REPORT_HAS(cmd_str(CMD_echo));
        if (!TEST_LIVE_DEVICE) {
            int len;
            const char *val = api_read_value(CMD_echo);
            char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                         memory_report_aeskey(TFA_SHARED_SECRET));
            u_assert(echo);
            u_assert_str_has(echo, KEYPATH_ONE);
            free(echo);
        }
        api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
        ASSERT_REPORT_HAS(sig_1_input);


        // recover fn4  hww success
        // verify  fn4  hww success
        // sign             fail
        snprintf(cmd, sizeof(cmd), "{\"source\":\"%s\", \"filename\":\"%s\", \"key\":\"key\"}",
                 attr_str(ATTR_backup), fn4);
        api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"key\",\"source\":\"%s\"}", fn4,
                 attr_str(ATTR_HWW));
        api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        api_format_send_cmd(cmd_str(CMD_sign), one_input, KEY_STANDARD);
        ASSERT_REPORT_HAS(cmd_str(CMD_echo));
        if (!TEST_LIVE_DEVICE) {
            int len;
            const char *val = api_read_value(CMD_echo);
            char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                         memory_report_aeskey(TFA_SHARED_SECRET));
            u_assert(echo);
            u_assert_str_has(echo, KEYPATH_ONE);
            free(echo);
        }
        api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
        ASSERT_REPORT_HAS_NOT(sig_1_input);


        // recover v23a u2f success
        // recover v23a hww success
        // verify  v23a u2f success
        // verify  v23u u2f success
        // verify  v23a hww success
        // verify  v23h hww success
        // sign             success
        snprintf(cmd, sizeof(cmd), "{\"source\":\"%s\", \"filename\":\"%s\"}",
                 attr_str(ATTR_U2F_load), tb_v2_3a);
        api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        snprintf(cmd, sizeof(cmd), "{\"source\":\"%s\", \"filename\":\"%s\", \"key\":\"key\"}",
                 attr_str(ATTR_backup), tb_v2_3a);
        api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", tb_v2_3a,
                 attr_str(ATTR_U2F));
        api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"source\":\"%s\"}", tb_v2_3u,
                 attr_str(ATTR_U2F));
        api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"key\",\"source\":\"%s\"}",
                 tb_v2_3a, attr_str(ATTR_HWW));
        api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"key\",\"source\":\"%s\"}",
                 tb_v2_3h, attr_str(ATTR_HWW));
        api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        api_format_send_cmd(cmd_str(CMD_sign), one_input, KEY_STANDARD);
        ASSERT_REPORT_HAS(cmd_str(CMD_echo));
        if (!TEST_LIVE_DEVICE) {
            int len;
            const char *val = api_read_value(CMD_echo);
            char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                         memory_report_aeskey(TFA_SHARED_SECRET));
            u_assert(echo);
            u_assert_str_has(echo, KEYPATH_ONE);
            free(echo);
        }
        api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
        ASSERT_REPORT_HAS(sig_1_input);


        // recover fn4  hww success
        // verify  fn4  hww success
        // sign             fail
        snprintf(cmd, sizeof(cmd), "{\"source\":\"%s\", \"filename\":\"%s\", \"key\":\"key\"}",
                 attr_str(ATTR_backup), fn4);
        api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        snprintf(cmd, sizeof(cmd), "{\"check\":\"%s\",\"key\":\"key\",\"source\":\"%s\"}", fn4,
                 attr_str(ATTR_HWW));
        api_format_send_cmd(cmd_str(CMD_backup), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        api_format_send_cmd(cmd_str(CMD_sign), one_input, KEY_STANDARD);
        ASSERT_REPORT_HAS(cmd_str(CMD_echo));
        if (!TEST_LIVE_DEVICE) {
            int len;
            const char *val = api_read_value(CMD_echo);
            char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                         memory_report_aeskey(TFA_SHARED_SECRET));
            u_assert(echo);
            u_assert_str_has(echo, KEYPATH_ONE);
            free(echo);
        }
        api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
        ASSERT_REPORT_HAS_NOT(sig_1_input);


        // recover v22  hww success
        // recover v22  u2f fail
        // sign             success
        snprintf(cmd, sizeof(cmd), "{\"source\":\"%s\", \"filename\":\"%s\", \"key\":\"key\"}",
                 attr_str(ATTR_backup), tb_v2_2);
        api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
        ASSERT_SUCCESS;

        snprintf(cmd, sizeof(cmd), "{\"source\":\"%s\", \"filename\":\"%s\"}",
                 attr_str(ATTR_U2F_load), tb_v2_2);
        api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
        ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SEED_INVALID));

        // sign
        api_format_send_cmd(cmd_str(CMD_sign), one_input, KEY_STANDARD);
        ASSERT_REPORT_HAS(cmd_str(CMD_echo));
        if (!TEST_LIVE_DEVICE) {
            int len;
            const char *val = api_read_value(CMD_echo);
            char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                         memory_report_aeskey(TFA_SHARED_SECRET));
            u_assert(echo);
            u_assert_str_has(echo, KEYPATH_ONE);
            free(echo);
        }
        api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
        ASSERT_REPORT_HAS(sig_1_input);
    }


    // clean up sd card
    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), KEY_STANDARD);
    ASSERT_SUCCESS;
}


static void tests_device(void)
{
    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_ping), "", NULL);
    ASSERT_REPORT_HAS(attr_str(ATTR_false));
    ASSERT_REPORT_HAS(cmd_str(CMD_device));
    ASSERT_REPORT_HAS(attr_str(ATTR_version));
    ASSERT_REPORT_HAS(DIGITAL_BITBOX_VERSION);

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_ping), "", NULL);
    ASSERT_REPORT_HAS(attr_str(ATTR_password));
    ASSERT_REPORT_HAS(cmd_str(CMD_device));
    ASSERT_REPORT_HAS(attr_str(ATTR_version));
    ASSERT_REPORT_HAS(DIGITAL_BITBOX_VERSION);

    api_format_send_cmd(cmd_str(CMD_led), attr_str(ATTR_blink), KEY_STANDARD);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_led), "invalid_cmd", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_led), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_seed), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_seed), "{\"source\":\"create\",\"filename\":\"junk\"}",
                        KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_KEY));

    api_format_send_cmd(cmd_str(CMD_seed),
                        "{\"source\":\"create\",\"key\":\"\",\"filename\":\"junk\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_KEY));

    api_format_send_cmd(cmd_str(CMD_seed),
                        "{\"source\":\"create\",\"key\":\"key\",\"filename\":\"\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_seed),
                        "{\"source\":\"create\",\"key\":\"key\",\"filename\":\"&^;:\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_BAD_CHAR));

    api_format_send_cmd(cmd_str(CMD_xpub), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_reset), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_backup), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_KEY));

    api_format_send_cmd(cmd_str(CMD_backup), "{\"key\":\"password\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_backup), "{\"filename\":\"b.pdf\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_KEY));

    api_format_send_cmd(cmd_str(CMD_random), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_device), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_ecdh), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_bootloader), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), KEY_STANDARD);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_seed),
                        "{\"source\":\"create\", \"filename\":\"c.pdf\", \"key\":\"password\"}", KEY_STANDARD);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_ecdh),
                        "{ \"hash_ecdh\" : \"6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b\" }",
                        KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_ecdh));

    api_format_send_cmd(cmd_str(CMD_backup), "{\"filename\":\"b.pdf\", \"key\":\"password\"}",
                        KEY_STANDARD);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_lock), KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_seed),
                        "{\"source\":\"create\", \"filename\":\"l.pdf\", \"key\":\"password\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_LOCKED));

    api_format_send_cmd(cmd_str(CMD_ecdh),
                        "{ \"hash_ecdh\" : \"6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b\" }",
                        KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_LOCKED));

    api_format_send_cmd(cmd_str(CMD_backup), "{\"filename\":\"b.pdf\", \"key\":\"password\"}",
                        KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_LOCKED));

    api_format_send_cmd("invalid_cmd", "invalid_cmd", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_device), "invalid_cmd", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_info), KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    ASSERT_REPORT_HAS(attr_str(ATTR_sdcard));
    ASSERT_REPORT_HAS(attr_str(ATTR_serial));
    ASSERT_REPORT_HAS(attr_str(ATTR_version));
    ASSERT_REPORT_HAS(attr_str(ATTR_bootlock));
    ASSERT_REPORT_HAS(attr_str(ATTR_name));
    ASSERT_REPORT_HAS(attr_str(ATTR_id));
    ASSERT_REPORT_HAS_NOT("\"id\":\"\"");
    ASSERT_REPORT_HAS("\"seeded\":true");
    ASSERT_REPORT_HAS("\"lock\":true");
    ASSERT_REPORT_HAS("\"U2F\":true");
    if (!TEST_LIVE_DEVICE) {
        yajl_val json_node = yajl_tree_parse(api_read_decrypted_report(), NULL, 0);
        const char *ciphertext_path[] = { cmd_str(CMD_device), attr_str(ATTR_TFA), (const char *) 0 };
        const char *ciphertext = YAJL_GET_STRING(yajl_tree_get(json_node, ciphertext_path,
                                 yajl_t_string));
        u_assert_int_eq(!ciphertext, 0);
        int decrypt_len;
        char *dec = cipher_aes_b64_hmac_decrypt((const unsigned char *)ciphertext,
                                                strlens(ciphertext),
                                                &decrypt_len, memory_report_aeskey(TFA_SHARED_SECRET));
        u_assert(dec);
        u_assert_str_eq(dec, VERIFYPASS_CRYPT_TEST);
        free(dec);
        yajl_tree_free(json_node);
    }



    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_info), KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    ASSERT_REPORT_HAS(attr_str(ATTR_sdcard));
    ASSERT_REPORT_HAS(attr_str(ATTR_serial));
    ASSERT_REPORT_HAS(attr_str(ATTR_version));
    ASSERT_REPORT_HAS(attr_str(ATTR_bootlock));
    ASSERT_REPORT_HAS(attr_str(ATTR_name));
    ASSERT_REPORT_HAS(attr_str(ATTR_id));
    ASSERT_REPORT_HAS("\"id\":\"\"");
    ASSERT_REPORT_HAS("\"seeded\":false");
    ASSERT_REPORT_HAS("\"lock\":false");
    ASSERT_REPORT_HAS("\"U2F\":true");

    api_format_send_cmd(cmd_str(CMD_bootloader), attr_str(ATTR_unlock), KEY_STANDARD);
    ASSERT_REPORT_HAS(attr_str(ATTR_unlock));
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_info), KEY_STANDARD);
    ASSERT_REPORT_HAS("\"bootlock\":false");

    api_format_send_cmd(cmd_str(CMD_bootloader), attr_str(ATTR_lock), KEY_STANDARD);
    ASSERT_REPORT_HAS(attr_str(ATTR_lock));
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_info), KEY_STANDARD);
    ASSERT_REPORT_HAS("\"bootlock\":true");

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), KEY_STANDARD);
    ASSERT_SUCCESS;

    if (!TEST_LIVE_DEVICE) {
        commander_force_reset();
    }
}


static void tests_input(void)
{
    api_reset_device();

    if (!TEST_LIVE_DEVICE) {
        api_send_cmd("", NULL);
        ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_NO_INPUT));

        api_send_cmd(NULL, NULL);
        ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_NO_INPUT));
    }

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_SUCCESS;

    api_send_cmd("{\"name\": \"name\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, KEY_STANDARD);
    ASSERT_SUCCESS;

    api_send_cmd("{\"name\": \"name\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    api_send_cmd("{\"name\": \"name\"}", NULL);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name\": \"name\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    api_send_cmd("{\"name\": \"name\", \"name\": \"name\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_MULT_CMD));

#ifndef CONTINUOUS_INTEGRATION
// YAJL does not free allocated space for these improper JSON strings
// so skip valgrind checks in travis CI.
    api_send_cmd("\"name\": \"name\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{name\": \"name\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name: \"name\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name\": \"name}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name\": \"name\"", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name\": \"name\", }", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name\": \"name\", \"name\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name\": \"name\", \"name\": }", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name\": \"na\\nme\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_BAD_CHAR));

    api_send_cmd("{\"name\": \"na\\r\\\\ \\/ \\f\\b\\tme\\\"\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_BAD_CHAR));
#endif

    api_send_cmd("{\"name\": null}", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    api_send_cmd("{\"name\": \"na\\u0066me\\ufc00\\u0000\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_BAD_CHAR));

    api_send_cmd("{\"name\": \"shouldnotacceptdelim2" SD_PDF_DELIM2_S "\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SD_BAD_CHAR));

    int i;
    for (i = 0; i < COMMANDER_MAX_ATTEMPTS - 1; i++) {
        api_send_cmd("{\"name\": \"name\"}", NULL);
        ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));
        if (i < COMMANDER_TOUCH_ATTEMPTS) {
            ASSERT_REPORT_HAS(flag_msg(DBB_WARN_RESET));
        } else {
            ASSERT_REPORT_HAS(flag_msg(DBB_WARN_RESET_TOUCH));
        }
    }
    api_send_cmd("{\"name\": \"name\"}", NULL);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_RESET));
}


static void tests_password(void)
{
    char cmd[512], xpub_std[112], xpub_hdn[112], xpub_tst[112];
    char keypath[] = "m/44'/0'/0'/0/0";

    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_name), "", NULL);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_NO_PASSWORD));

    api_format_send_cmd(cmd_str(CMD_name), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_NO_PASSWORD));

    api_format_send_cmd(cmd_str(CMD_password), "123", NULL);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_PASSWORD_LEN));

    api_format_send_cmd(cmd_str(CMD_password), "", NULL);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_PASSWORD_LEN));

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_format_send_cmd(cmd_str(CMD_password), "123", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_PASSWORD_LEN));


    //
    // Test ECDH
    //
    const char *ecdh_priv_hex =
        "769a3f70c6f4820e717fd50477e218f0c7456013ded246043b40ac49e9accd5f";
    const char *ecdh_pub_hex =
        "035f40a5dcd64074194b3f88767dbf7a527ddd227d7734b68dd2e9d25c2d20d080";
    char ecdh_cmd[256];
    snprintf(ecdh_cmd, 256, "{\"pubkey\":\"%s\"}", ecdh_pub_hex);

    uint8_t ecdh_priv[32];
    memcpy(ecdh_priv, utils_hex_to_uint8(ecdh_priv_hex), 32);
    uint8_t ecdh_pub[33];
    memcpy(ecdh_pub, utils_hex_to_uint8(ecdh_pub_hex), 33);

    uint8_t hash_ecdh[SHA256_DIGEST_LENGTH];
    sha256_Raw(ecdh_pub, 33, hash_ecdh);

    char hash_ecdh_hex[65];
    memcpy(hash_ecdh_hex, utils_uint8_to_hex(hash_ecdh, SHA256_DIGEST_LENGTH), 65);

    char ecdh_hash_cmd[256];
    snprintf(ecdh_hash_cmd, 256, "{\"hash_pubkey\":\"%s\"}", hash_ecdh_hex);

    api_format_send_cmd(cmd_str(CMD_ecdh), ecdh_hash_cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    ASSERT_REPORT_HAS(cmd_str(CMD_hash_pubkey));

    const char *response_hash_ecdh = api_read_decrypted_report();

    yajl_val json_node_0 = yajl_tree_parse(response_hash_ecdh, NULL, 0);
    u_assert(json_node_0);
    u_assert(YAJL_IS_OBJECT(json_node_0));

    const char *path[] = { cmd_str(CMD_ecdh), NULL };
    yajl_val ecdh_node = yajl_tree_get(json_node_0, path, yajl_t_any);
    const char *path_hash_ecdh[] = { cmd_str(CMD_hash_pubkey), NULL };
    const char *out_hash_ecdh_hex = YAJL_GET_STRING(yajl_tree_get(ecdh_node,
                                    path_hash_ecdh, yajl_t_string));

    // we should have received a hex representation of the hashed ECDH public key of the bitbox.
    u_assert(out_hash_ecdh_hex);

    uint8_t out_hash_ecdh[32];
    memcpy(out_hash_ecdh, utils_hex_to_uint8(out_hash_ecdh_hex), 32 * sizeof(uint8_t));

    api_format_send_cmd(cmd_str(CMD_ecdh), ecdh_cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    ASSERT_REPORT_HAS(cmd_str(CMD_pubkey));
    // TODO: assert that hash of response is the same as the hash received above.

    const char *response_ecdh = api_read_decrypted_report();

    yajl_val json_node_1 = yajl_tree_parse(response_ecdh, NULL, 0);
    u_assert(json_node_1);
    u_assert(YAJL_IS_OBJECT(json_node_1));

    ecdh_node = yajl_tree_get(json_node_1, path, yajl_t_any);
    const char *path_ecdh[] = { cmd_str(CMD_pubkey), NULL };
    const char *out_ecdh_pub_hex = YAJL_GET_STRING(yajl_tree_get(ecdh_node, path_ecdh,
                                   yajl_t_string));
    u_assert(out_ecdh_pub_hex);

    uint8_t out_ecdh_pub[33];
    memcpy(out_ecdh_pub, utils_hex_to_uint8(out_ecdh_pub_hex), 33);

    uint8_t calculated_hash[32];
    sha256_Raw(out_ecdh_pub, 33, calculated_hash);
    u_assert_mem_eq(out_hash_ecdh, calculated_hash, SHA256_DIGEST_LENGTH);

    api_format_send_cmd(cmd_str(CMD_ecdh), cmd_str(CMD_challenge), KEY_STANDARD);

    yajl_tree_free(json_node_0);
    yajl_tree_free(json_node_1);

    // TODO: test blinking by writing the number that has been blinked into a buffer and read from
    // this buffer to compare it with the calculated shared secret.

    //
    // Test hidden password
    //

    // Login to hidden wallet -> error (hidden key not set)
    api_format_send_cmd(cmd_str(CMD_name), "", KEY_HIDDEN);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));
    // Set hidden key - error no master
    snprintf(cmd, sizeof(cmd), "{\"%s\":\"%s\",\"%s\":\"%s\"}", cmd_str(CMD_password),
             hidden_pwd, cmd_str(CMD_key), hidden_pwd);
    api_format_send_cmd(cmd_str(CMD_hidden_password), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_MASTER));
    // Erase backups
    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), KEY_STANDARD);
    ASSERT_SUCCESS;
    // Seed wallets
    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"create\",\"filename\":\"h.pdf\",\"key\":\"%s\"}", tests_pwd);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;
    // Send deprecated command to set hidden key
    api_format_send_cmd(cmd_str(CMD_hidden_password), "1234", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));
    // Send incommplete command to set hidden key
    snprintf(cmd, sizeof(cmd), "{\"%s\":\"%s\"}", cmd_str(CMD_password), hidden_pwd);
    api_format_send_cmd(cmd_str(CMD_hidden_password), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));
    // Send incommplete command to set hidden key
    snprintf(cmd, sizeof(cmd), "{\"%s\":\"%s\"}", cmd_str(CMD_key), hidden_pwd);
    api_format_send_cmd(cmd_str(CMD_hidden_password), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));
    // Set hidden key with wrong length -> hidden key not reset
    snprintf(cmd, sizeof(cmd), "{\"%s\":\"123\",\"%s\":\"%s\"}", cmd_str(CMD_password),
             cmd_str(CMD_key), hidden_pwd);
    api_format_send_cmd(cmd_str(CMD_hidden_password), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_PASSWORD_LEN));
    // Access hidden wallet - should fail if no key set
    api_format_send_cmd(cmd_str(CMD_xpub), keypath, KEY_HIDDEN);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));
    // Set hidden key
    snprintf(cmd, sizeof(cmd), "{\"%s\":\"%s\",\"%s\":\"%s\"}", cmd_str(CMD_password),
             hidden_pwd, cmd_str(CMD_key), hidden_pwd);
    api_format_send_cmd(cmd_str(CMD_hidden_password), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;
    // Login to hidden wallet
    api_format_send_cmd(cmd_str(CMD_name), "", KEY_HIDDEN);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    ASSERT_REPORT_HAS(DEVICE_DEFAULT_NAME);
    // Change standard key to hidden key from standard wallet -> error collision
    // -> delete hidden key and set standard key to hidden key
    api_format_send_cmd(cmd_str(CMD_password), hidden_pwd, KEY_STANDARD);
    if (!TEST_U2FAUTH_HIJACK) {
        api_decrypt_report((char *)HID_REPORT, KEY_HIDDEN);
        ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_PW_COLLIDE));
    }
    // Login to standard wallet (hidden key)
    api_format_send_cmd(cmd_str(CMD_name), "", KEY_HIDDEN);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    ASSERT_REPORT_HAS(DEVICE_DEFAULT_NAME);
    // Reset standard password
    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, KEY_HIDDEN);
    if (!TEST_U2FAUTH_HIJACK) {
        ASSERT_SUCCESS;
    }
    // Login to standard wallet (hidden key)
    api_format_send_cmd(cmd_str(CMD_name), "", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    ASSERT_REPORT_HAS(DEVICE_DEFAULT_NAME);
    // Login to hidden wallet -> error (hidden key not set)
    api_format_send_cmd(cmd_str(CMD_name), "", KEY_HIDDEN);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));

    // Reset hidden key
    snprintf(cmd, sizeof(cmd), "{\"%s\":\"%s\",\"%s\":\"%s\"}", cmd_str(CMD_password),
             hidden_pwd, cmd_str(CMD_key), hidden_pwd);
    api_format_send_cmd(cmd_str(CMD_hidden_password), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;
    // Login to hidden wallet
    api_format_send_cmd(cmd_str(CMD_name), "", KEY_HIDDEN);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    ASSERT_REPORT_HAS(DEVICE_DEFAULT_NAME);
    // Change (hidden) key to standard key from hidden wallet -> error collision
    // -> delete hidden key and activate standard key
    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, KEY_HIDDEN);
    if (!TEST_U2FAUTH_HIJACK) {
        api_decrypt_report((char *)HID_REPORT, KEY_STANDARD);
        ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_PW_COLLIDE));
    }
    // Login to hidden wallet -> error (hidden key not set)
    api_format_send_cmd(cmd_str(CMD_name), "", KEY_HIDDEN);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));
    // Login to standard wallet
    api_format_send_cmd(cmd_str(CMD_name), "", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    ASSERT_REPORT_HAS(DEVICE_DEFAULT_NAME);

    // Reset hidden key
    snprintf(cmd, sizeof(cmd), "{\"%s\":\"%s\",\"%s\":\"%s\"}", cmd_str(CMD_password),
             hidden_pwd, cmd_str(CMD_key), hidden_pwd);
    api_format_send_cmd(cmd_str(CMD_hidden_password), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;
    // Login to hidden wallet
    api_format_send_cmd(cmd_str(CMD_name), "", KEY_HIDDEN);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    ASSERT_REPORT_HAS(DEVICE_DEFAULT_NAME);
    // Change hidden key to standard key from standard wallet -> error collision
    // -> deletes hidden key
    snprintf(cmd, sizeof(cmd), "{\"%s\":\"%s\",\"%s\":\"%s\"}", cmd_str(CMD_password),
             tests_pwd, cmd_str(CMD_key), tests_pwd);
    api_format_send_cmd(cmd_str(CMD_hidden_password), cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_PW_COLLIDE));
    // Login to standard wallet
    api_format_send_cmd(cmd_str(CMD_name), "", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    ASSERT_REPORT_HAS(DEVICE_DEFAULT_NAME);
    // Login to hidden wallet -> error (hidden key not set)
    api_format_send_cmd(cmd_str(CMD_name), "", KEY_HIDDEN);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));

    // Verify hidden wallet uses different keys
    memset(xpub_std, 0, sizeof(xpub_std));
    memset(xpub_hdn, 0, sizeof(xpub_hdn));
    memset(xpub_tst, 0, sizeof(xpub_tst));
    // Reset hidden key
    snprintf(cmd, sizeof(cmd), "{\"%s\":\"%s\",\"%s\":\"%s\"}", cmd_str(CMD_password),
             hidden_pwd, cmd_str(CMD_key), hidden_pwd);
    api_format_send_cmd(cmd_str(CMD_hidden_password), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;
    // Get standard wallet xpub
    api_format_send_cmd(cmd_str(CMD_xpub), keypath, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    memcpy(xpub_std, api_read_value(CMD_xpub), sizeof(xpub_std));
    u_assert_str_not_eq(xpub_std, xpub_hdn);
    u_assert_str_not_eq(xpub_std, xpub_tst);
    // Get hidden wallet xpub and check that it is different
    api_format_send_cmd(cmd_str(CMD_xpub), keypath, KEY_HIDDEN);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    memcpy(xpub_hdn, api_read_value(CMD_xpub), sizeof(xpub_hdn));
    u_assert_str_not_eq(xpub_std, xpub_hdn);
    u_assert_str_not_eq(xpub_hdn, xpub_tst);
    // Change key in hidden wallet
    char tmp_pw[] = "tmp_pw";
    uint8_t tmp_key[32];
    sha256_Raw((const uint8_t *)tmp_pw, strlens(tmp_pw), tmp_key);
    sha256_Raw(tmp_key, MEM_PAGE_LEN, tmp_key);
    api_format_send_cmd(cmd_str(CMD_password), tmp_pw, KEY_HIDDEN);
    ASSERT_SUCCESS;
    // Login to hidden wallet
    api_format_send_cmd(cmd_str(CMD_name), "", tmp_key);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    // Get hidden wallet xpub and check that it is same (hidden wallet not reset on change pw)
    api_format_send_cmd(cmd_str(CMD_xpub), keypath, tmp_key);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    memcpy(xpub_tst, api_read_value(CMD_xpub), sizeof(xpub_tst));
    u_assert_str_not_eq(xpub_std, xpub_tst);
    u_assert_str_eq(xpub_hdn, xpub_tst);
    // Change key in hidden wallet back to original
    api_format_send_cmd(cmd_str(CMD_password), hidden_pwd, tmp_key);
    ASSERT_SUCCESS;
    // Change hidden key in hidden wallet -> error disabled
    snprintf(cmd, sizeof(cmd), "{\"%s\":\"%s\",\"%s\":\"%s\"}", cmd_str(CMD_password),
             "junk_pwd", cmd_str(CMD_key), "junk_pwd");
    api_format_send_cmd(cmd_str(CMD_hidden_password), cmd, KEY_HIDDEN);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_LOCKED));
    // Get hidden wallet xpub and check that it is same (hidden wallet not reset)
    api_format_send_cmd(cmd_str(CMD_xpub), keypath, KEY_HIDDEN);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    memcpy(xpub_tst, api_read_value(CMD_xpub), sizeof(xpub_tst));
    u_assert_str_not_eq(xpub_std, xpub_tst);
    u_assert_str_eq(xpub_hdn, xpub_tst);
    // Login to standard wallet
    api_format_send_cmd(cmd_str(CMD_name), "", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    // Use hidden key to seed from backup
    // -> puts the hidden wallet into a standard wallet
    // -> erases hidden wallet
    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"backup\",\"filename\":\"h.pdf\",\"key\":\"%s\"}", hidden_pwd);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;
    // Get standard wallet xpub
    // xpubs equal
    api_format_send_cmd(cmd_str(CMD_xpub), keypath, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    memcpy(xpub_tst, api_read_value(CMD_xpub), sizeof(xpub_tst));
    u_assert_str_eq(xpub_hdn, xpub_tst);
    u_assert_str_not_eq(xpub_std, xpub_tst);
    // Error logging in hidden wallet
    api_format_send_cmd(cmd_str(CMD_name), "", KEY_HIDDEN);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));
    // Use standard key to seed from backup
    // -> get the original standard wallet
    snprintf(cmd, sizeof(cmd),
             "{\"source\":\"backup\",\"filename\":\"h.pdf\",\"key\":\"%s\"}", tests_pwd);
    api_format_send_cmd(cmd_str(CMD_seed), cmd, KEY_STANDARD);
    ASSERT_SUCCESS;
    // Get standard wallet xpub
    // xpubs equal
    api_format_send_cmd(cmd_str(CMD_xpub), keypath, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    memcpy(xpub_tst, api_read_value(CMD_xpub), sizeof(xpub_tst));
    u_assert_str_eq(xpub_std, xpub_tst);
    u_assert_str_not_eq(xpub_hdn, xpub_tst);
}

static void tests_echo_tfa(void)
{
    char hash_sign[] =
        "{\"meta\":\"hash\", \"data\":[{\"keypath\":\"" KEYPATH_ONE "\", \"hash\":\"" HASH_DEFAULT
        "\"}] }";
    char hash_sign2[] =
        "{\"meta\":\"hash\", \"data\":[{\"keypath\":\"" KEYPATH_ONE
        "\", \"hash\":\"ffff456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}] }";
    char hash_sign3[] =
        "{\"meta\":\"hash\", \"data\":[{\"keypath\":\"" KEYPATH_ONE
        "\", \"hash\":\"456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}] }";

    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_sign), hash_sign2, KEY_STANDARD);
    u_assert_int_eq((strstr(api_read_decrypted_report(), cmd_str(CMD_echo)) ||
                     strstr(api_read_decrypted_report(), flag_msg(DBB_ERR_KEY_MASTER))), 1);

    api_format_send_cmd(cmd_str(CMD_sign), hash_sign2, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_MASTER));

    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_lock), KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_KEY_MASTER));

    api_format_send_cmd(cmd_str(CMD_seed),
                        "{\"source\":\"create\", \"filename\":\"c.pdf\", \"key\":\"password\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    //
    // Test ECDH
    //
    const char *ecdh_pub_hex =
        "028d3bce812ac027fdea0e4ad98b2549a90bb9aa996396eec6bb1a8ed56e6976b8";
    char ecdh_cmd[256];
    snprintf(ecdh_cmd, 256, "{\"pubkey\":\"%s\"}", ecdh_pub_hex);

    uint8_t ecdh_pub[34];
    memcpy(ecdh_pub, utils_hex_to_uint8(ecdh_pub_hex), 33);
    ecdh_pub[33] = 0;

    uint8_t hash_ecdh[SHA256_DIGEST_LENGTH];
    sha256_Raw(ecdh_pub, 33, hash_ecdh);

    char hash_ecdh_hex[65];
    memcpy(hash_ecdh_hex, utils_uint8_to_hex(hash_ecdh, SHA256_DIGEST_LENGTH), 64);
    hash_ecdh_hex[64] = 0;

    char ecdh_hash_cmd[256];
    snprintf(ecdh_hash_cmd, 256, "{\"hash_pubkey\":\"%s\"}", hash_ecdh_hex);

    api_format_send_cmd(cmd_str(CMD_ecdh), ecdh_hash_cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    ASSERT_REPORT_HAS(cmd_str(CMD_hash_pubkey));

    api_format_send_cmd(cmd_str(CMD_ecdh), ecdh_cmd, KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
    ASSERT_REPORT_HAS(cmd_str(CMD_ecdh));
    // end test ECDH

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), KEY_STANDARD);
    ASSERT_SUCCESS

    api_format_send_cmd(cmd_str(CMD_ecdh), "invalid_cmd", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    // test echo
    api_format_send_cmd(cmd_str(CMD_sign), hash_sign, KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));

    api_format_send_cmd(cmd_str(CMD_device), "info", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_sign), hash_sign, KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));

    api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(cmd_str(CMD_echo));
    ASSERT_REPORT_HAS(cmd_str(CMD_recid));
    ASSERT_REPORT_HAS(cmd_str(CMD_sig));

    api_format_send_cmd(cmd_str(CMD_sign), hash_sign, KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));

    api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(cmd_str(CMD_echo));
    ASSERT_REPORT_HAS(cmd_str(CMD_recid));
    ASSERT_REPORT_HAS(cmd_str(CMD_sig));

    // test hash length
    api_format_send_cmd(cmd_str(CMD_sign), hash_sign3, KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));

    api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SIGN_HASH_LEN));

    // test locked
    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_lock), KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_sign), hash_sign, KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        int len;
        const char *val = api_read_value(CMD_echo);
        char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                     memory_report_aeskey(TFA_SHARED_SECRET));
        u_assert(echo);
        u_assert_str_has(echo, cmd_str(CMD_pin));
        free(echo);
    }

    api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SIGN_TFA_PIN));

    api_format_send_cmd(cmd_str(CMD_sign), hash_sign, KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        int len;
        const char *val = api_read_value(CMD_echo);
        char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                     memory_report_aeskey(TFA_SHARED_SECRET));
        u_assert(echo);
        u_assert_str_has(echo, cmd_str(CMD_pin));
        free(echo);
    }

    // correct pin
    api_format_send_cmd(cmd_str(CMD_sign), "{\"pin\":\"0001\"}", KEY_STANDARD);
    if (TEST_LIVE_DEVICE) {
        ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SIGN_TFA_PIN));
    } else {
        ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
        ASSERT_REPORT_HAS(cmd_str(CMD_recid));
        ASSERT_REPORT_HAS(cmd_str(CMD_sig));
    }

    api_format_send_cmd(cmd_str(CMD_seed), "{\"source\":\"create\", \"key\":\"password\"}",
                        KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_LOCKED));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_LOCKED));
}


static int recover_public_key_verify_sig(const char *sig, const char *hash,
        const char *recid, const char *pubkey)
{
#ifdef ECC_USE_SECP256K1_LIB
    static secp256k1_context *ctx = NULL;
    uint8_t hash_b[32];
    uint8_t sig_b[64];
    uint8_t recid_b;
    size_t public_key_len = 33;
    uint8_t pubkey_33[public_key_len];
    secp256k1_ecdsa_recoverable_signature signature_r;
    secp256k1_ecdsa_signature signature, signorm;
    secp256k1_pubkey pubkey_recover;

    memcpy(hash_b, utils_hex_to_uint8(hash), 32);
    memcpy(sig_b, utils_hex_to_uint8(sig), 64);
    memcpy(&recid_b, utils_hex_to_uint8(recid), 1);
    memset(pubkey_33, 0, public_key_len);

    if (!ctx) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        uint8_t rndm[32] = {0};
        random_bytes(rndm, sizeof(rndm), 0);
        if (secp256k1_context_randomize(ctx, rndm)) {
            /* pass */
        }
    }

    secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &signature_r, sig_b, recid_b);
    if (!secp256k1_ecdsa_recover(ctx, &pubkey_recover, &signature_r, hash_b)) {
        return 1;
    }
    secp256k1_ec_pubkey_serialize(ctx, pubkey_33, &public_key_len, &pubkey_recover,
                                  SECP256K1_EC_COMPRESSED);

    secp256k1_ecdsa_recoverable_signature_convert(ctx, &signature, &signature_r);
    secp256k1_ecdsa_signature_normalize(ctx, &signorm, &signature);

    if (!secp256k1_ecdsa_verify(ctx, &signorm, hash_b, &pubkey_recover)) {
        return 1;
    }

    if (!MEMEQ(utils_hex_to_uint8(pubkey), pubkey_33, public_key_len)) {
        return 1;
    }

#else
    (void) sig;
    (void) hash;
    (void) recid;
    (void) pubkey;
#endif
    return 0; // success
}


// sig_1_input is normalized (low-S). The non-normalized value is "61e87a12a111987e3bef9dffd4b30a0322f2cc74e65a19aa551a3eaa8f417d0be7cfa5ad06beac67f09192bc7c213396b8277831b939d52e95a97749772f112f"
const char sig_1_input[] =
    "61e87a12a111987e3bef9dffd4b30a0322f2cc74e65a19aa551a3eaa8f417d0b18305a52f94153980f6e6d4383decc68028764b4f60ecb0d2a28e74359073012";
const char sig_2_input_1[] =
    "e26c9b19c927d7e6e374d7f1734dd0a4e1ee266a164b2f282d95a0d07dbf04f0486594e9d853cbfab1cc556e76e8212d2db6c871c8c775876525d20acc478439";
const char sig_2_input_2[] =
    "529e01807f073dd80a0c9c2b3cc9130a06b88c033577ccc426a383eaadac5b7201923aef70ded7509adfa6282fcb6ff9f0fba16f87c82d5c9810c3da3029cc7d";


static void tests_sign(void)
{
    int i, res;
    char one_input[] = "{\"meta\":\"_meta_data_\", \"data\":[{\"hash\":\"" HASH_INPUT_ONE
                       "\", \"keypath\":\"" KEYPATH_ONE "\"}]}";
    char two_inputs[] = "{\"meta\":\"_meta_data_\", \"data\":[{\"hash\":\"" HASH_INPUT_TWO_1
                        "\", \"keypath\":\"" KEYPATH_TWO "\"},{\"hash\":\"" HASH_INPUT_TWO_2 "\", \"keypath\":\""
                        KEYPATH_THREE "\"}]}";
    char hashstr[] = "{\"hash\":\"" HASH_DEFAULT "\", \"keypath\":\"m/44p/0p/0p/0/9999\"}";
    char hashstart[] = "{\"meta\":\"" HASH_DEFAULT "\", \"checkpub\":[{\"pubkey\":\""
                       PUBKEY_ZERO "\", \"keypath\":\"m/44p/0p/0p/1/9999\"}], \"data\": [";
    char maxhashes[COMMANDER_REPORT_SIZE];
    char hashoverflow[COMMANDER_REPORT_SIZE];

    i = 0;
    memset(hashoverflow, 0, sizeof(hashoverflow));
    memset(maxhashes, 0, sizeof(maxhashes));
    strcat(maxhashes, hashstart);
    strcat(maxhashes, hashstr);
    i++;
    while ((i + 1) * COMMANDER_SIG_LEN < COMMANDER_ARRAY_MAX) {
        strcat(maxhashes, ",");
        strcat(maxhashes, hashstr);
        i++;
    }
    strcat(hashoverflow, maxhashes);
    strcat(hashoverflow, ",");
    strcat(hashoverflow, hashstr);
    strcat(hashoverflow, "]}");
    strcat(maxhashes, "]}");
    u_print_info("Max hashes to sign: %i\n", i);
    u_assert_int_eq(i >= COMMANDER_NUM_SIG_MIN, 1);


    char checkpub[] =
        "{\"meta\":\"<<meta data here>>\", \"data\": [{\"hash\":\"" HASH_INPUT_ONE
        "\", \"keypath\":\"" KEYPATH_BASE "\"},{\"hash\":\"" HASH_DEFAULT "\", \"keypath\":\""
        KEYPATH_BASE "\"}], \"checkpub\":[{\"pubkey\":\"" PUBKEY_ZERO "\", \"keypath\":\""
        KEYPATH_TWO "\"},{\"pubkey\":\"" PUBKEY_INPUT_TWO_1 "\", \"keypath\":\""
        KEYPATH_TWO"\"}]}";
    char check_1[] =
        "\"pubkey\":\"" PUBKEY_ZERO "\", \"present\":false";
    char check_2[] =
        "\"pubkey\":\"" PUBKEY_INPUT_TWO_1 "\", \"present\":true";
    // check_sig_1 is normalized (low-S). The non-normalized value is "2a756acd456b732e779cd7e7f05ae2855ee3128bca75cb8fc805bba8c6fbabba924e51ccac655024165bb302d00174d842e5960cde8c448a6a900d26fe342fe9"
    char check_sig_1[] =
        "2a756acd456b732e779cd7e7f05ae2855ee3128bca75cb8fc805bba8c6fbabba6db1ae33539aafdbe9a44cfd2ffe8b2677c946d9d0bc5bb155425165d2021158";
    char check_sig_2[] =
        "3323b353e9974ab1eb452eca19e1dc4dad0556dba668089c8c1214ca09b58ad12c82da6671a65f9b3803c1fe7a14f35d885caebce701f972641748738275782b";
    char check_pubkey[] =
        "02df86355b162c942b89e297c1e919f40943834d448b0b6b4538556e805ea4e18c";

    char checkpub_wrong_addr_len[] =
        "{\"meta\":\"<<meta data here>>\", \"data\": [{\"hash\":\"" HASH_INPUT_ONE
        "\", \"keypath\":\"" KEYPATH_BASE "\"},{\"hash\":\"" HASH_DEFAULT "\", \"keypath\":\""
        KEYPATH_BASE "\"}], \"checkpub\":[{\"pubkey\":\"00\", \"keypath\":\"" KEYPATH_TWO
        "\"},{\"pubkey\":\"" PUBKEY_INPUT_TWO_1 "\", \"keypath\":\"" KEYPATH_TWO "\"}]}";

    char checkpub_missing_parameter[] =
        "{\"meta\":\"<<meta data here>>\", \"data\": [{\"hash\":\"" HASH_INPUT_ONE
        "\", \"keypath\":\"" KEYPATH_BASE "\"},{\"hash\":\"" HASH_DEFAULT "\", \"keypath\":\""
        KEYPATH_BASE "\"}], \"checkpub\":[{\"pubkey\":\"" PUBKEY_INPUT_TWO_1 "\"}]}";

    char sig_device_1[64 * 2 + 1];
    char sig_device_2[64 * 2 + 1];
    char recid_device_1[2 + 1];
    char recid_device_2[2 + 1];
    char pubkey_device_1[33 * 2 + 1];
    char pubkey_device_2[33 * 2 + 1];
    HDNode node;
    memset(&node, 0, sizeof(HDNode));


    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_SUCCESS;

    // backup
    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), KEY_STANDARD);
    ASSERT_SUCCESS;

    if (!TEST_LIVE_DEVICE) {
        // copy test sd_files to sd card directory
        // some files have seeds with known high-S signatures
        // and the code should normalize these (low-S; tested below)
        int ret = system("cp ../tests/sd_files/*.pdf tests/digitalbitbox/");
        u_assert(ret == 0);

        // seed from backup file
        char seed[512];
        snprintf(seed, sizeof(seed), "{\"source\":\"%s\", \"filename\":\"%s\", \"key\":\"key\"}",
                 attr_str(ATTR_backup), "test_backup.pdf");
        api_format_send_cmd(cmd_str(CMD_seed), seed, KEY_STANDARD);
    } else {
        api_format_send_cmd(cmd_str(CMD_seed),
                            "{\"source\":\"create\", \"filename\":\"temp.pdf\", \"key\":\"key\"}",
                            KEY_STANDARD);
    }
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    // clean up sd card
    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), KEY_STANDARD);
    ASSERT_SUCCESS;


    // missing parameters
    api_format_send_cmd(cmd_str(CMD_sign), checkpub_missing_parameter, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_sign),
                        "{\"data\":[{\"keypath\":\"m/\"}]}",
                        KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_sign),
                        "{\"data\":[{\"hash\":\"empty\"}]}",
                        KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    // data is not an array
    api_format_send_cmd(cmd_str(CMD_sign),
                        "{\"data\":{\"hash\":\"empty\"}}",
                        KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));


    // sign max number of hashes per sign command
    api_format_send_cmd(cmd_str(CMD_sign), maxhashes, KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));

    api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    // sign 1 more than max number of hashes per sign command
    api_format_send_cmd(cmd_str(CMD_sign), hashoverflow, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_REPORT_BUF));

    api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_REPORT_BUF));

    // sig using no inputs
    api_format_send_cmd(cmd_str(CMD_sign), "{\"meta\":\"_meta_data_\", \"data\":[]}",
                        KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    // invalid data field
    api_format_send_cmd(cmd_str(CMD_sign), "{\"meta\":\"_meta_data_\", \"data\":true}",
                        KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_INVALID_CMD));

    // sign using one input
    api_format_send_cmd(cmd_str(CMD_xpub), KEYPATH_ONE, KEY_STANDARD);
    hdnode_deserialize(api_read_value(CMD_xpub), &node);
    snprintf(pubkey_device_1, sizeof(pubkey_device_1), "%s",
             utils_uint8_to_hex(node.public_key, 33));

    api_format_send_cmd(cmd_str(CMD_sign), one_input, KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        int len;
        const char *val = api_read_value(CMD_echo);
        char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                     memory_report_aeskey(TFA_SHARED_SECRET));
        u_assert(echo);
        u_assert_str_has_not(echo, cmd_str(CMD_recid));
        u_assert_str_has(echo, "_meta_data_");
        u_assert_str_has(echo, KEYPATH_ONE);
        free(echo);
    }

    api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_recid));

    memcpy(sig_device_1, api_read_array_value(CMD_sign, CMD_sig, 0), sizeof(sig_device_1));
    memcpy(recid_device_1, api_read_array_value(CMD_sign, CMD_recid, 0),
           sizeof(recid_device_1));

    u_assert_int_eq(0, recover_public_key_verify_sig(sig_device_1, HASH_INPUT_ONE,
                    recid_device_1, pubkey_device_1));

    if (!TEST_LIVE_DEVICE) {
        // If TESTING, a deterministic seed is loaded when 'raw' is specified
        ASSERT_REPORT_HAS(sig_1_input);
        u_assert_str_eq(sig_device_1, sig_1_input);
        u_assert_str_eq(pubkey_device_1, PUBKEY_INPUT_ONE);
#ifdef ECC_USE_SECP256K1_LIB
        u_assert_str_eq(recid_device_1, RECID_01);
#else
        u_assert_str_eq(recid_device_1, RECID_EE);
#endif
    } else {
        // Random seed generated on device
        ASSERT_REPORT_HAS_NOT(sig_1_input);
        u_assert_str_not_eq(sig_device_1, sig_1_input);
        u_assert_str_not_eq(pubkey_device_1, PUBKEY_INPUT_ONE);
    }

    // sign using two inputs
    api_format_send_cmd(cmd_str(CMD_xpub), KEYPATH_TWO, KEY_STANDARD);
    hdnode_deserialize(api_read_value(CMD_xpub), &node);
    snprintf(pubkey_device_1, sizeof(pubkey_device_1), "%s",
             utils_uint8_to_hex(node.public_key, 33));

    api_format_send_cmd(cmd_str(CMD_xpub), KEYPATH_THREE, KEY_STANDARD);
    hdnode_deserialize(api_read_value(CMD_xpub), &node);
    snprintf(pubkey_device_2, sizeof(pubkey_device_2), "%s",
             utils_uint8_to_hex(node.public_key, 33));

    api_format_send_cmd(cmd_str(CMD_sign), two_inputs, KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        int len;
        const char *val = api_read_value(CMD_echo);
        char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                     memory_report_aeskey(TFA_SHARED_SECRET));
        u_assert(echo);
        u_assert_str_has_not(echo, cmd_str(CMD_recid));
        u_assert_str_has(echo, "_meta_data_");
        u_assert_str_has(echo, KEYPATH_TWO);
        free(echo);
    }

    api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_sign));

    memcpy(sig_device_1, api_read_array_value(CMD_sign, CMD_sig, 0), sizeof(sig_device_1));
    memcpy(sig_device_2, api_read_array_value(CMD_sign, CMD_sig, 1), sizeof(sig_device_2));
    memcpy(recid_device_1, api_read_array_value(CMD_sign, CMD_recid, 0),
           sizeof(recid_device_1));
    memcpy(recid_device_2, api_read_array_value(CMD_sign, CMD_recid, 1),
           sizeof(recid_device_2));

    u_assert_int_eq(0, recover_public_key_verify_sig(sig_device_1, HASH_INPUT_TWO_1,
                    recid_device_1, pubkey_device_1));
    u_assert_int_eq(0, recover_public_key_verify_sig(sig_device_2, HASH_INPUT_TWO_2,
                    recid_device_2, pubkey_device_2));

    if (!TEST_LIVE_DEVICE) {
        // If TESTING, a deterministic seed is loaded when 'raw' is specified
        ASSERT_REPORT_HAS(sig_2_input_1);
        ASSERT_REPORT_HAS(sig_2_input_2);
        ASSERT_REPORT_HAS(cmd_str(CMD_recid));
        u_assert_str_eq(sig_device_1, sig_2_input_1);
        u_assert_str_eq(sig_device_2, sig_2_input_2);
        u_assert_str_eq(pubkey_device_1, PUBKEY_INPUT_TWO_1);
        u_assert_str_eq(pubkey_device_2, PUBKEY_INPUT_TWO_2);
#ifdef ECC_USE_SECP256K1_LIB
        u_assert_str_eq(recid_device_1, RECID_01);
        u_assert_str_eq(recid_device_2, RECID_01);
#else
        u_assert_str_eq(recid_device_1, RECID_EE);
        u_assert_str_eq(recid_device_2, RECID_EE);
#endif
    } else {
        // Random seed generated on device
        ASSERT_REPORT_HAS_NOT(sig_2_input_1);
        ASSERT_REPORT_HAS_NOT(sig_2_input_2);
        ASSERT_REPORT_HAS(cmd_str(CMD_recid));
        u_assert_str_not_eq(sig_device_1, sig_2_input_1);
        u_assert_str_not_eq(sig_device_2, sig_2_input_2);
        u_assert_str_not_eq(pubkey_device_1, PUBKEY_INPUT_TWO_1);
        u_assert_str_not_eq(pubkey_device_2, PUBKEY_INPUT_TWO_2);
    }

    // test checkpub
    api_format_send_cmd(cmd_str(CMD_xpub), KEYPATH_BASE, KEY_STANDARD);
    hdnode_deserialize(api_read_value(CMD_xpub), &node);
    snprintf(pubkey_device_1, sizeof(pubkey_device_1), "%s",
             utils_uint8_to_hex(node.public_key, 33));
    snprintf(pubkey_device_2, sizeof(pubkey_device_2), "%s",
             utils_uint8_to_hex(node.public_key, 33));

    api_format_send_cmd(cmd_str(CMD_sign), checkpub, KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        int len;
        const char *val = api_read_value(CMD_echo);
        char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                     memory_report_aeskey(TFA_SHARED_SECRET));
        u_assert(echo);
        u_assert_str_has_not(echo, cmd_str(CMD_recid));
        u_assert_str_has(echo, "\"meta\":");
        u_assert_str_has(echo, check_1);
        u_assert_str_has(echo, check_2);
        free(echo);
    }

    api_format_send_cmd(cmd_str(CMD_sign), "", KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_sign));

    memcpy(sig_device_1, api_read_array_value(CMD_sign, CMD_sig, 0), sizeof(sig_device_1));
    memcpy(sig_device_2, api_read_array_value(CMD_sign, CMD_sig, 1), sizeof(sig_device_2));
    memcpy(recid_device_1, api_read_array_value(CMD_sign, CMD_recid, 0),
           sizeof(recid_device_1));
    memcpy(recid_device_2, api_read_array_value(CMD_sign, CMD_recid, 1),
           sizeof(recid_device_1));

    u_assert_int_eq(0, recover_public_key_verify_sig(sig_device_1, HASH_INPUT_ONE,
                    recid_device_1, pubkey_device_1));
    u_assert_int_eq(0, recover_public_key_verify_sig(sig_device_2, HASH_DEFAULT,
                    recid_device_2, pubkey_device_2));

    if (!TEST_LIVE_DEVICE) {
        // If TESTING, a deterministic seed is loaded when 'raw' is specified
        ASSERT_REPORT_HAS(check_sig_1);
        ASSERT_REPORT_HAS(check_sig_2);
        u_assert_str_eq(sig_device_1, check_sig_1);
        u_assert_str_eq(sig_device_2, check_sig_2);
        u_assert_str_eq(pubkey_device_1, check_pubkey);
#ifdef ECC_USE_SECP256K1_LIB
        u_assert_str_eq(recid_device_1, RECID_01);
        u_assert_str_eq(recid_device_2, RECID_01);
#else
        u_assert_str_eq(recid_device_1, RECID_EE);
        u_assert_str_eq(recid_device_2, RECID_EE);
#endif
    } else {
        // Random seed generated on device
        ASSERT_REPORT_HAS_NOT(check_sig_1);
        ASSERT_REPORT_HAS_NOT(check_sig_2);
        u_assert_str_not_eq(sig_device_1, check_sig_1);
        u_assert_str_not_eq(sig_device_2, check_sig_2);
        u_assert_str_not_eq(pubkey_device_1, check_pubkey);
    }

    api_format_send_cmd(cmd_str(CMD_sign), checkpub_wrong_addr_len, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SIGN_PUBKEY_LEN));

    api_format_send_cmd(cmd_str(CMD_sign), checkpub_wrong_addr_len, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SIGN_PUBKEY_LEN));


    // lock to get TFA PINs
    int pin_err_count = 0;
    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_lock), KEY_STANDARD);
    ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));

    // sign using one input
    api_format_send_cmd(cmd_str(CMD_sign), one_input, KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        int len;
        const char *val = api_read_value(CMD_echo);
        char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                     memory_report_aeskey(TFA_SHARED_SECRET));
        u_assert(echo);
        u_assert_str_has_not(echo, cmd_str(CMD_recid));
        u_assert_str_has(echo, "_meta_data_");
        u_assert_str_has(echo, KEYPATH_ONE);
        u_assert_str_has(echo, cmd_str(CMD_pin));
        free(echo);
    }

    // skip sending pin
    api_format_send_cmd(cmd_str(CMD_sign), one_input, KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SIGN_TFA_PIN));
    if (TEST_LIVE_DEVICE) {
        pin_err_count++;
    }

    // send wrong pin
    api_format_send_cmd(cmd_str(CMD_sign), one_input, KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        int len;
        const char *val = api_read_value(CMD_echo);
        char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                     memory_report_aeskey(TFA_SHARED_SECRET));
        u_assert(echo);
        u_assert_str_has_not(echo, cmd_str(CMD_recid));
        u_assert_str_has(echo, "_meta_data_");
        u_assert_str_has(echo, KEYPATH_ONE);
        u_assert_str_has(echo, cmd_str(CMD_pin));
        free(echo);
    }

    api_format_send_cmd(cmd_str(CMD_sign), "{\"pin\":\"000\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SIGN_TFA_PIN));

    // send correct pin
    api_format_send_cmd(cmd_str(CMD_sign), one_input, KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        int len;
        const char *val = api_read_value(CMD_echo);
        char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                     memory_report_aeskey(TFA_SHARED_SECRET));
        u_assert(echo);
        u_assert_str_has_not(echo, cmd_str(CMD_recid));
        u_assert_str_has(echo, "_meta_data_");
        u_assert_str_has(echo, KEYPATH_ONE);
        u_assert_str_has(echo, cmd_str(CMD_pin));
        free(echo);
    } else {
        pin_err_count++;
    }

    api_format_send_cmd(cmd_str(CMD_sign), "{\"pin\":\"0001\"}", KEY_STANDARD);
    if (!TEST_LIVE_DEVICE) {
        ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
        ASSERT_REPORT_HAS(cmd_str(CMD_sign));
        ASSERT_REPORT_HAS(sig_1_input);
        ASSERT_REPORT_HAS(cmd_str(CMD_recid));
        res = recover_public_key_verify_sig(sig_1_input, HASH_INPUT_ONE, RECID_01,
                                            PUBKEY_INPUT_ONE);
        u_assert_int_eq(res, 0);
    } else {
        pin_err_count++;
    }


    // sign using two inputs
    api_format_send_cmd(cmd_str(CMD_sign), two_inputs, KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        int len;
        const char *val = api_read_value(CMD_echo);
        char *echo = cipher_aes_b64_hmac_decrypt((const unsigned char *)val, strlens(val), &len,
                     memory_report_aeskey(TFA_SHARED_SECRET));
        u_assert(echo);
        u_assert_str_has_not(echo, cmd_str(CMD_recid));
        u_assert_str_has(echo, "_meta_data_");
        u_assert_str_has(echo, KEYPATH_TWO);
        free(echo);
    }

    // send correct pin
    api_format_send_cmd(cmd_str(CMD_sign), "{\"pin\":\"0001\"}", KEY_STANDARD);
    if (!TEST_LIVE_DEVICE) {
        ASSERT_REPORT_HAS_NOT(attr_str(ATTR_error));
        ASSERT_REPORT_HAS(cmd_str(CMD_sign));
        ASSERT_REPORT_HAS(sig_2_input_1);
        ASSERT_REPORT_HAS(sig_2_input_2);
        ASSERT_REPORT_HAS(cmd_str(CMD_recid));
        res = recover_public_key_verify_sig(sig_2_input_1, HASH_INPUT_TWO_1, RECID_01,
                                            PUBKEY_INPUT_TWO_1);
        u_assert_int_eq(res, 0);
        res = recover_public_key_verify_sig(sig_2_input_2, HASH_INPUT_TWO_2, RECID_01,
                                            PUBKEY_INPUT_TWO_2);
        u_assert_int_eq(res, 0);
    } else {
        pin_err_count++;
    }

    for (; pin_err_count < COMMANDER_MAX_ATTEMPTS - 1; pin_err_count++) {
        api_format_send_cmd(cmd_str(CMD_sign), one_input, KEY_STANDARD);
        ASSERT_REPORT_HAS(cmd_str(CMD_echo));
        api_format_send_cmd(cmd_str(CMD_sign), "{\"pin\":\"000\"}", KEY_STANDARD);
        ASSERT_REPORT_HAS(flag_msg(DBB_ERR_SIGN_TFA_PIN));
        ASSERT_REPORT_HAS(flag_msg(DBB_WARN_RESET));
    }

    api_format_send_cmd(cmd_str(CMD_sign), one_input, KEY_STANDARD);
    ASSERT_REPORT_HAS(cmd_str(CMD_echo));
    api_format_send_cmd(cmd_str(CMD_sign), "{\"pin\":\"000\"}", KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_RESET));
    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_lock), KEY_STANDARD);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_NO_PASSWORD));
}


static void tests_memory_setup(void)
{
    uint8_t key_00[MEM_PAGE_LEN];
    uint8_t key_FE[MEM_PAGE_LEN];
    uint8_t key_FF[MEM_PAGE_LEN];
    memset(key_00, 0x00, MEM_PAGE_LEN);
    memset(key_FE, 0xFE, MEM_PAGE_LEN);
    memset(key_FF, 0xFF, MEM_PAGE_LEN);

    api_reset_device();

    if (!TEST_LIVE_DEVICE && !TEST_U2FAUTH_HIJACK) {
        api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
        ASSERT_REPORT_HAS(flag_msg(DBB_ERR_MEM_SETUP));
    }

    // Run twice, first time accesses one-time factory install code
    // Memory map updating tested in unit_test.c
    memory_setup();
    memory_setup();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, NULL);
    ASSERT_SUCCESS;

    api_format_send_cmd(cmd_str(CMD_led), "abort", key_00);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_format_send_cmd(cmd_str(CMD_led), "abort", key_FE);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_format_send_cmd(cmd_str(CMD_led), "abort", key_FF);
    ASSERT_REPORT_HAS(flag_msg(DBB_ERR_IO_JSON_PARSE));
}


static void run_utests(void)
{
    u_run_test(tests_memory_setup);// Keep first
    u_run_test(tests_name);
    u_run_test(tests_u2f);
    u_run_test(tests_echo_tfa);
    u_run_test(tests_password);
    u_run_test(tests_random);
    u_run_test(tests_device);
    u_run_test(tests_input);
    u_run_test(tests_seed_xpub_backup);
    u_run_test(tests_sign);

    if (!U_TESTS_FAIL) {
        printf("\nALL %i TESTS PASSED\n\n", U_TESTS_RUN);
    } else {
        printf("\n%i of %i TESTS PASSED\n\n", U_TESTS_RUN - U_TESTS_FAIL, U_TESTS_RUN);
    }
}


uint32_t __stack_chk_guard = 0;

extern void __attribute__((noreturn)) __stack_chk_fail(void);
void __attribute__((noreturn)) __stack_chk_fail(void)
{
    printf("\n\nError: stack smashing detected!\n\n");
    abort();
}


int main(void)
{
    // Test the C code API
    TEST_LIVE_DEVICE = 0;
    __stack_chk_guard = random_uint32(0);
    ecc_context_init();
#ifdef ECC_USE_SECP256K1_LIB
    bitcoin_ecc.ecc_context_init();
#endif
    // Fill test aes keys for standard and hidden wallets
    sha256_Raw((const uint8_t *)tests_pwd, strlens(tests_pwd), KEY_STANDARD);
    sha256_Raw(KEY_STANDARD, MEM_PAGE_LEN, KEY_STANDARD);
    sha256_Raw((const uint8_t *)hidden_pwd, strlens(hidden_pwd), KEY_HIDDEN);
    sha256_Raw(KEY_HIDDEN, MEM_PAGE_LEN, KEY_HIDDEN);

    printf("\n\nInternal API result via standard interface:\n");
    TEST_U2FAUTH_HIJACK = 0;
    run_utests();
    printf("\nInternal API result via hijack interface:\n");
    TEST_U2FAUTH_HIJACK = 1;
    run_utests();

#ifndef CONTINUOUS_INTEGRATION
    // Live test of the HID API
    // Requires the hidapi library to be installed:
    //     http://www.signal11.us/oss/hidapi/
    TEST_LIVE_DEVICE = 1;
    if (api_hid_init() == DBB_ERROR) {
        printf("\n\nNot testing HID API. A device is not connected.\n\n");
    } else {
        printf("\n\nHID API result via standard interface:\n");
        TEST_U2FAUTH_HIJACK = 0;
        run_utests();
        printf("\nHID API result via hijack interface:\n");
        TEST_U2FAUTH_HIJACK = 1;
        run_utests();
    }
#endif

    ecc_context_destroy();
#ifdef ECC_USE_SECP256K1_LIB
    bitcoin_ecc.ecc_context_destroy();
#endif
    return U_TESTS_FAIL;
}
