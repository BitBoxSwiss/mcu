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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ecc.h"
#include "utest.h"
#include "utils.h"
#include "flags.h"
#include "random.h"
#include "commander.h"
#include "yajl/src/api/yajl_tree.h"

#include "api.h"


int U_TESTS_RUN = 0;
int U_TESTS_FAIL = 0;


static void tests_seed_xpub_backup(void)
{
    char name0[] = "name0";
    char key[] = "password";
    char xpub0[112], xpub1[112], *echo;
    char seed_c[512], seed_b[512], back[512], check[512], erase_file[512];
    char filename[] = "tests_backup.txt";
    char filename_create[] = "tests_backup_c.txt";
    char filename_bad[] = "tests_backup_bad<.txt";
    char keypath[] = "m/44\'/0\'/";
    char seed_create[] =
        "{\"source\":\"create\", \"filename\":\"seed_create.pdf\", \"key\":\"password\"}";
    char seed_create_2[] =
        "{\"source\":\"create\", \"filename\":\"seed_create_2.pdf\", \"key\":\"password\"}";
    char seed_create_bad[] =
        "{\"source\":\"create\", \"filename\":\"../seed_create_bad.pdf\", \"key\":\"password\"}";
    char seed_xpriv[] =
        "{\"source\":\"xprv9s21ZrQH143K2MkmL8hdyZk5uwTPEqkwS72jXDt5DGRtUVrfYiAvAnGmxmP3J5Z3BG5uQcy5UYUMDsqisyXEDNCG2uzixsckhnfCrJxKVme\"}";
    char seed_xpriv_wrong_len[] =
        "{\"source\":\"xprv9s21ZrQH143K2MkmL8hdyZk5uwTPEqkwS72jXDt5DGRtUVrfYiAvAnGmxmP3J5Z3BG5uQcy5UYUMDsqisyXEDNCG2uzixsckhnfCrJxKVm\"}";

    snprintf(seed_c, sizeof(seed_c),
             "{\"source\":\"%s\", \"filename\":\"%s\", \"key\":\"%s\"}", attr_str(ATTR_create),
             filename_create, key);
    snprintf(seed_b, sizeof(seed_b), "{\"source\":\"%s\",\"key\":\"%s\"}", filename, key);
    snprintf(back, sizeof(back), "{\"filename\":\"%s\",\"key\":\"%s\"}", filename, key);
    snprintf(check, sizeof(check), "{\"check\":\"%s\",\"key\":\"%s\"}", filename, key);

    // erase
    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    // rename
    api_format_send_cmd(cmd_str(CMD_name), name0, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    u_assert_str_eq(name0, api_read_value(CMD_name));

    memset(xpub0, 0, sizeof(xpub0));
    memset(xpub1, 0, sizeof(xpub1));
    api_format_send_cmd(cmd_str(CMD_backup), back, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_KEY_MASTER));

    // create
    api_format_send_cmd(cmd_str(CMD_xpub), keypath, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_seed), seed_c, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_xpub), keypath, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    memcpy(xpub0, api_read_value(CMD_xpub), sizeof(xpub0));
    u_assert_str_not_eq(xpub0, xpub1);

    if (!TEST_LIVE_DEVICE) {
        echo = api_read_value_decrypt(CMD_echo, PASSWORD_VERIFY);
        u_assert_str_eq(xpub0, echo);
    }

    // check backup list and erase
    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), filename_create);

    // backup
    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    u_assert_str_has_not(utils_read_decrypted_report(), filename_create);
    if (TEST_LIVE_DEVICE) {
        u_assert_str_has_not(utils_read_decrypted_report(), flag_msg(DBB_ERR_SD_ERASE));
    }

    api_format_send_cmd(cmd_str(CMD_backup), back, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    // erase device
    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    // check has default name
    api_format_send_cmd(cmd_str(CMD_name), "", PASSWORD_STAND);
    u_assert_str_eq(DEVICE_DEFAULT_NAME, api_read_value(CMD_name));

    // load backup
    api_format_send_cmd(cmd_str(CMD_seed), seed_b, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_name), "", PASSWORD_STAND);
    u_assert_str_eq(name0, api_read_value(CMD_name));

    api_format_send_cmd(cmd_str(CMD_xpub), keypath, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    memcpy(xpub1, api_read_value(CMD_xpub), sizeof(xpub1));
    if (!TEST_LIVE_DEVICE) {
        echo = api_read_value_decrypt(CMD_echo, PASSWORD_VERIFY);
        u_assert_str_eq(xpub0, echo);
    }

    // check xpubs
    u_assert_str_eq(xpub0, xpub1);

    // check backup list and erase
    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), filename);
    u_assert_str_has_not(utils_read_decrypted_report(), filename_create);

    api_format_send_cmd(cmd_str(CMD_backup), check, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_success));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), filename);
    u_assert_str_has_not(utils_read_decrypted_report(), filename_create);

    api_format_send_cmd(cmd_str(CMD_backup), check, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_success));








    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_seed), seed_create, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), "seed_create.pdf");

    if (TEST_LIVE_DEVICE) {
        api_format_send_cmd(cmd_str(CMD_seed), seed_create_bad, PASSWORD_STAND);
        u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SD_BAD_CHAR));

        api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), PASSWORD_STAND);
        u_assert_str_has_not(utils_read_decrypted_report(), "../seed_create_bad.pdf");
    }

    // test sd list overflow
    if (TEST_LIVE_DEVICE) {
        char long_backup_name[SD_FILEBUF_LEN_MAX / 8];
        char lbn[SD_FILEBUF_LEN_MAX / 8];
        size_t i;

        memset(long_backup_name, '-', sizeof(long_backup_name));

        for (i = 0; i < SD_FILEBUF_LEN_MAX / sizeof(long_backup_name); i++) {
            snprintf(lbn, sizeof(lbn), "%lu%s", i, long_backup_name);
            snprintf(back, sizeof(back), "{\"filename\":\"%s\", \"key\":\"password\"}", lbn);
            api_format_send_cmd(cmd_str(CMD_backup), back, PASSWORD_STAND);
            u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

            api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), PASSWORD_STAND);
            u_assert_str_has_not(utils_read_decrypted_report(), cmd_str(CMD_warning));
        }

        snprintf(lbn, sizeof(lbn), "%lu%s", i, long_backup_name);
        snprintf(back, sizeof(back), "{\"filename\":\"%s\", \"key\":\"password\"}", lbn);
        api_format_send_cmd(cmd_str(CMD_backup), back, PASSWORD_STAND);
        u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

        api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), PASSWORD_STAND);
        u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_warning));

        api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), PASSWORD_STAND);
        u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    }

    // test keypath
    api_format_send_cmd(cmd_str(CMD_xpub), "m/111", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), "\"xpub\":");

    api_format_send_cmd(cmd_str(CMD_xpub), "111", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "/111", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "m", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "m111", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/a", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/!", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_KEY_CHILD));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/-111", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_KEY_CHILD));

    // test create seeds differ
    memset(xpub0, 0, sizeof(xpub0));
    memset(xpub1, 0, sizeof(xpub1));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/0", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    memcpy(xpub0, api_read_value(CMD_xpub), sizeof(xpub0));
    u_assert_str_not_eq(xpub0, xpub1);

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), filename);

    if (TEST_LIVE_DEVICE) {
        snprintf(back, sizeof(back), "{\"filename\":\"%s\", \"key\":\"password\"}", filename_bad);
        api_format_send_cmd(cmd_str(CMD_backup), back, PASSWORD_STAND);
        u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SD_BAD_CHAR));

        snprintf(check, sizeof(check), "{\"check\":\"%s\", \"key\":\"password\"}", filename_bad);
        api_format_send_cmd(cmd_str(CMD_backup), check, PASSWORD_STAND);
        u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_success));
        u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SD_BAD_CHAR));
    }

    snprintf(back, sizeof(back), "{\"filename\":\"%s\", \"key\":\"password\"}", filename);
    api_format_send_cmd(cmd_str(CMD_backup), back, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    snprintf(check, sizeof(check), "{\"check\":\"%s\", \"key\":\"password\"}", filename);
    api_format_send_cmd(cmd_str(CMD_backup), check, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_success));

    api_format_send_cmd(cmd_str(CMD_seed), seed_create_2, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/0", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    memcpy(xpub1, api_read_value(CMD_xpub), sizeof(xpub0));
    u_assert_str_not_eq(xpub0, xpub1);

    api_format_send_cmd(cmd_str(CMD_backup), check, PASSWORD_STAND);
    if (TEST_LIVE_DEVICE) {
        u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SD_NO_MATCH));
    }

    // test cannot overwrite existing backup file
    api_format_send_cmd(cmd_str(CMD_seed), seed_create_2, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SD_OPEN_FILE));

    // test erase single backup file
    if (!TEST_LIVE_DEVICE) {
        // testing buffer gets overwritten by seed command, so reset it
        api_format_send_cmd(cmd_str(CMD_backup), back, PASSWORD_STAND);
        u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    }

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), filename);

    snprintf(erase_file, sizeof(erase_file), "{\"%s\":\"%s\"}", attr_str(ATTR_erase),
             filename);
    api_format_send_cmd(cmd_str(CMD_backup), erase_file, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    if (TEST_LIVE_DEVICE) {
        snprintf(erase_file, sizeof(erase_file), "{\"%s\":\"%s\"}", attr_str(ATTR_erase),
                 filename_bad);
        api_format_send_cmd(cmd_str(CMD_backup), erase_file, PASSWORD_STAND);
        u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SD_BAD_CHAR));
    }

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), filename);

    // test xpriv seed
    memset(xpub0, 0, sizeof(xpub0));
    memset(xpub1, 0, sizeof(xpub1));

    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_seed), seed_xpriv, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/0", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    memcpy(xpub0, api_read_value(CMD_xpub), sizeof(xpub0));
    u_assert_str_not_eq(xpub0, xpub1);

    api_format_send_cmd(cmd_str(CMD_seed), seed_xpriv_wrong_len, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SEED_INVALID));

    api_format_send_cmd(cmd_str(CMD_xpub), "m/0", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    memcpy(xpub1, api_read_value(CMD_xpub), sizeof(xpub0));
    u_assert_str_eq(xpub0, xpub1);

    // clean up sd card
    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
}


static void tests_random(void)
{
    char number0[32] = {0};
    char number1[32] = {0};

    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_random), attr_str(ATTR_pseudo), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));

    memcpy(number0, api_read_value(CMD_random), sizeof(number0));

    api_format_send_cmd(cmd_str(CMD_random), attr_str(ATTR_pseudo), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    memcpy(number1, api_read_value(CMD_random), sizeof(number1));
    u_assert_str_not_eq(number0, number1);

    api_format_send_cmd(cmd_str(CMD_random), attr_str(ATTR_true), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    memcpy(number0, api_read_value(CMD_random), sizeof(number0));

    api_format_send_cmd(cmd_str(CMD_random), attr_str(ATTR_true), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    memcpy(number1, api_read_value(CMD_random), sizeof(number1));
    u_assert_str_not_eq(number0, number1);

    api_format_send_cmd(cmd_str(CMD_random), "invalid_cmd", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));
}


static void tests_name(void)
{
    char name0[] = "name0";
    char name1[] = "name1";

    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_name), name0, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    u_assert_str_eq(name0, api_read_value(CMD_name));

    api_format_send_cmd(cmd_str(CMD_name), name1, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    u_assert_str_eq(name1, api_read_value(CMD_name));

    api_format_send_cmd(cmd_str(CMD_name), "", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    u_assert_str_eq(name1, api_read_value(CMD_name));
}


static void tests_device(void)
{
    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_ping), "", PASSWORD_NONE);
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_false));

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_ping), "", PASSWORD_NONE);
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_password));

    api_format_send_cmd(cmd_str(CMD_led), attr_str(ATTR_blink), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_success));

    api_format_send_cmd(cmd_str(CMD_led), attr_str(ATTR_abort), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_success));

    api_format_send_cmd(cmd_str(CMD_led), "invalid_cmd", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_led), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_seed), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_seed), "{\"source\":\"create\"}", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SD_KEY));

    api_format_send_cmd(cmd_str(CMD_xpub), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_reset), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_backup), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SD_KEY));

    api_format_send_cmd(cmd_str(CMD_backup), "{\"key\":\"password\"}", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_backup), "{\"filename\":\"b.txt\"}", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SD_KEY));

    api_format_send_cmd(cmd_str(CMD_random), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_device), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_verifypass), "", PASSWORD_STAND);

    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_sign), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_bootloader), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_seed), "{\"source\":\"create\", \"key\":\"password\"}",
                        PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), AUTOBACKUP_FILENAME);

    api_format_send_cmd(cmd_str(CMD_seed),
                        "{\"source\":\"create\", \"filename\":\"c.pdf\", \"key\":\"password\"}", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_verifypass), attr_str(ATTR_create), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_backup), "{\"filename\":\"b.txt\", \"key\":\"password\"}",
                        PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_lock), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_seed),
                        "{\"source\":\"create\", \"filename\":\"l.pdf\", \"key\":\"password\"}", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_LOCKED));

    api_format_send_cmd(cmd_str(CMD_verifypass), attr_str(ATTR_create), PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_LOCKED));

    api_format_send_cmd(cmd_str(CMD_backup), "{\"filename\":\"b.txt\", \"key\":\"password\"}",
                        PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_LOCKED));

    api_format_send_cmd("invalid_cmd", "invalid_cmd", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_device), "invalid_cmd", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_info), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_sdcard));
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_serial));
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_version));
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_bootlock));
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_name));
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_id));
    u_assert_str_has_not(utils_read_decrypted_report(), "\"id\":\"\"");
    u_assert_str_has(utils_read_decrypted_report(), "\"seeded\":true");
    u_assert_str_has(utils_read_decrypted_report(), "\"lock\":true");
    if (!TEST_LIVE_DEVICE) {
        yajl_val json_node = yajl_tree_parse(utils_read_decrypted_report(), NULL, 0);
        const char *ciphertext_path[] = { cmd_str(CMD_device), attr_str(ATTR_TFA), (const char *) 0 };
        const char *ciphertext = YAJL_GET_STRING(yajl_tree_get(json_node, ciphertext_path,
                                 yajl_t_string));
        u_assert_int_eq(!ciphertext, 0);
        int decrypt_len;
        char *dec = aes_cbc_b64_decrypt((const unsigned char *)ciphertext, strlens(ciphertext),
                                        &decrypt_len, PASSWORD_VERIFY);
        u_assert_str_eq(dec, VERIFYPASS_CRYPT_TEST);
        free(dec);
        yajl_tree_free(json_node);
    }

    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_info), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_sdcard));
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_serial));
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_version));
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_bootlock));
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_name));
    u_assert_str_has(utils_read_decrypted_report(), attr_str(ATTR_id));
    u_assert_str_has(utils_read_decrypted_report(), "\"id\":\"\"");
    u_assert_str_has(utils_read_decrypted_report(), "\"seeded\":false");
    u_assert_str_has(utils_read_decrypted_report(), "\"lock\":false");

    api_format_send_cmd(cmd_str(CMD_bootloader), attr_str(ATTR_unlock), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    if (TEST_LIVE_DEVICE) {
        api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_info), PASSWORD_STAND);
        u_assert_str_has(utils_read_decrypted_report(), "\"bootlock\":false");
    }

    api_format_send_cmd(cmd_str(CMD_bootloader), attr_str(ATTR_lock), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    if (TEST_LIVE_DEVICE) {
        api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_info), PASSWORD_STAND);
        u_assert_str_has(utils_read_decrypted_report(), "\"bootlock\":true");
    }

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    if (!TEST_LIVE_DEVICE) {
        commander_force_reset();
    }
}


static void tests_input(void)
{
    api_reset_device();

    if (!TEST_LIVE_DEVICE) {
        api_send_cmd("", PASSWORD_NONE);
        u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_NO_INPUT));

        api_send_cmd(NULL, PASSWORD_NONE);
        u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_NO_INPUT));
    }

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_send_cmd("{\"name\": \"name\"}", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_send_cmd("{\"name\": \"name\"}", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_send_cmd("{\"name\": \"name\"}", PASSWORD_NONE);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name\": \"name\"}", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_send_cmd("{\"name\": \"name\", \"name\": \"name\"}", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_MULT_CMD));

#ifndef CONTINUOUS_INTEGRATION
// YAJL does not free allocated space for these improper JSON strings
// so skip valgrind checks in travis CI.
    api_send_cmd("\"name\": \"name\"}", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{name\": \"name\"}", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name: \"name\"}", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name\": \"name}", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name\": \"name\"", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name\": \"name\", }", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name\": \"name\", \"name\"}", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name\": \"name\", \"name\": }", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_send_cmd("{\"name\": \"na\\nme\"}", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_send_cmd("{\"name\": \"na\\r\\\\ \\/ \\f\\b\\tme\\\"\"}", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
#endif

    api_send_cmd("{\"name\": null}", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_send_cmd("{\"name\": \"na\\u0066me\\ufc00\\u0000\"}", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    int i;
    for (i = 0; i < COMMANDER_MAX_ATTEMPTS - 1; i++) {
        api_send_cmd("{\"name\": \"name\"}", PASSWORD_NONE);
        u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_JSON_PARSE));
        u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_WARN_RESET));
    }
    api_send_cmd("{\"name\": \"name\"}", PASSWORD_NONE);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_RESET));
}


static void tests_password(void)
{
    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_name), "", PASSWORD_NONE);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_NO_PASSWORD));

    api_format_send_cmd(cmd_str(CMD_name), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_NO_PASSWORD));

    api_format_send_cmd(cmd_str(CMD_password), "123", PASSWORD_NONE);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_PASSWORD_LEN));

    api_format_send_cmd(cmd_str(CMD_password), "", PASSWORD_NONE);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_PASSWORD_LEN));

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_JSON_PARSE));

    api_format_send_cmd(cmd_str(CMD_password), "123", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_PASSWORD_LEN));

    // Test ECDH verifypass
    char ecdh[] =
        "{\"ecdh\":\"028d3bce812ac027fdea0e4ad98b2549a90bb9aa996396eec6bb1a8ed56e6976b8\"}";
    api_format_send_cmd(cmd_str(CMD_verifypass), ecdh, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_ecdh));
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_ciphertext));

    if (!TEST_LIVE_DEVICE) {
        yajl_val json_node = yajl_tree_parse(utils_read_decrypted_report(), NULL, 0);
        const char *ciphertext_path[] = { cmd_str(CMD_verifypass), cmd_str(CMD_ciphertext), (const char *) 0 };
        const char *ciphertext = YAJL_GET_STRING(yajl_tree_get(json_node, ciphertext_path,
                                 yajl_t_string));
        if (ciphertext) {
            int decrypt_len;
            char *dec = aes_cbc_b64_decrypt((const unsigned char *)ciphertext, strlens(ciphertext),
                                            &decrypt_len, PASSWORD_VERIFY);
            u_assert_str_eq(dec, VERIFYPASS_CRYPT_TEST);
            free(dec);
        }
        yajl_tree_free(json_node);
    }

    // Test reset password
    if (TEST_LIVE_DEVICE) {
        api_format_send_cmd(cmd_str(CMD_name), "", PASSWORD_RESET);
        u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_JSON_PARSE));
    }

    api_format_send_cmd(cmd_str(CMD_set_reset_password), reset_pwd, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_set_reset_password), "123", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_PASSWORD_LEN));

    api_format_send_cmd(cmd_str(CMD_password), reset_pwd, PASSWORD_STAND);
    if (!TEST_LIVE_DEVICE) {
        u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_PW_COLLIDE));
    }
    memory_write_aeskey(reset_pwd, strlens(reset_pwd), PASSWORD_STAND);

    api_format_send_cmd(cmd_str(CMD_name), "", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_STAND);
    if (!TEST_LIVE_DEVICE) {
        u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    }
    memory_write_aeskey(tests_pwd, strlens(tests_pwd), PASSWORD_STAND);

    api_format_send_cmd(cmd_str(CMD_set_reset_password), tests_pwd, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_PW_COLLIDE));

    api_format_send_cmd(cmd_str(CMD_name), "", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_set_reset_password), reset_pwd, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_name), "", PASSWORD_RESET);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_RESET));

    api_format_send_cmd(cmd_str(CMD_name), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_NO_PASSWORD));
}


static void tests_echo_tfa(void)
{
    char hash_sign[] =
        "{\"meta\":\"hash\", \"data\":[{\"keypath\":\"m/\", \"hash\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}] }";
    char hash_sign2[] =
        "{\"meta\":\"hash\", \"data\":[{\"keypath\":\"m/\", \"hash\":\"ffff456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}] }";
    char hash_sign3[] =
        "{\"meta\":\"hash\", \"data\":[{\"keypath\":\"m/\", \"hash\":\"456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}] }";

    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_sign), hash_sign2, PASSWORD_STAND);
    u_assert_int_eq((strstr(utils_read_decrypted_report(), cmd_str(CMD_echo)) ||
                     strstr(utils_read_decrypted_report(), flag_msg(DBB_ERR_KEY_MASTER))), 1);

    api_format_send_cmd(cmd_str(CMD_sign), hash_sign2, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_KEY_MASTER));

    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_lock), PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_KEY_MASTER));

    api_format_send_cmd(cmd_str(CMD_seed),
                        "{\"source\":\"create\", \"filename\":\"c.pdf\", \"key\":\"password\"}", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    // test verifypass
    api_format_send_cmd(cmd_str(CMD_verifypass), attr_str(ATTR_create), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_erase), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), VERIFYPASS_FILENAME);

    api_format_send_cmd(cmd_str(CMD_verifypass), attr_str(ATTR_export), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), VERIFYPASS_FILENAME);

    api_format_send_cmd(cmd_str(CMD_verifypass), "invalid_cmd", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    // test echo
    api_format_send_cmd(cmd_str(CMD_sign), hash_sign, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));

    api_format_send_cmd(cmd_str(CMD_device), "info", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_sign), hash_sign, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));

    api_format_send_cmd(cmd_str(CMD_sign), "", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), cmd_str(CMD_echo));
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_pubkey));
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_sig));

    api_format_send_cmd(cmd_str(CMD_sign), hash_sign, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));

    api_format_send_cmd(cmd_str(CMD_sign), "", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), cmd_str(CMD_echo));
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_pubkey));
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_sig));

    // test hash length
    api_format_send_cmd(cmd_str(CMD_sign), hash_sign3, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));

    api_format_send_cmd(cmd_str(CMD_sign), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SIGN_HASH_LEN));

    // test locked
    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_lock), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_sign), hash_sign, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_pin));
    }

    api_format_send_cmd(cmd_str(CMD_sign), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SIGN_TFA_PIN));

    api_format_send_cmd(cmd_str(CMD_sign), hash_sign, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_pin));
    }

    // correct pin
    api_format_send_cmd(cmd_str(CMD_sign), "{\"pin\":\"0001\"}", PASSWORD_STAND);
    if (TEST_LIVE_DEVICE) {
        u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SIGN_TFA_PIN));
    } else {
        u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
        u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_pubkey));
        u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_sig));
    }

    api_format_send_cmd(cmd_str(CMD_seed), "{\"source\":\"create\", \"key\":\"password\"}",
                        PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_LOCKED));

    api_format_send_cmd(cmd_str(CMD_verifypass), attr_str(ATTR_export), PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_LOCKED));

    api_format_send_cmd(cmd_str(CMD_backup), attr_str(ATTR_list), PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_LOCKED));
}


#ifdef ECC_USE_UECC_LIB
const char hash_1_input[] =
    "41fa23804d6fe53c296a5ac93a2e21719f9c6f20b2645d04d047150087cd812acedefc98a7d87f1379efb84dc684ab947dc4e583d2c3e1d50f372012b3d8c95e";
const char hash_2_input_1[] =
    "031145194147dada762c77ff85fd5cb493f56596de20f235c35507cd72716134e49cbe288c46f90da19bd1552c406e64425169520d433113a78b480ca3c5d340";
const char hash_2_input_2[] =
    "d4464e76d679b062ec867c7ebb961fc27cab810ccd6198bd993acef5a84273bcf16b256cfd77768df1bbce20333904c5e93873cee26ac446afdd62a5394b73ad";
#else
const char hash_1_input[] =
    "41fa23804d6fe53c296a5ac93a2e21719f9c6f20b2645d04d047150087cd812a31210367582780ec861047b2397b546a3ce9f762dc84be66b09b3e7a1c5d77e3";
const char hash_2_input_1[] =
    "031145194147dada762c77ff85fd5cb493f56596de20f235c35507cd727161341b6341d773b906f25e642eaad3bf919a785d7394a2056f28184716802c706e01";
const char hash_2_input_2[] =
    "d4464e76d679b062ec867c7ebb961fc27cab810ccd6198bd993acef5a84273bc0e94da93028889720e4431dfccc6fb38d1766917ccdddbf50ff4fbe796eacd94";
#endif


static void tests_sign(void)
{
    char one_input[] =
        "{\"meta\":\"_meta_data_\", \"data\":[{\"hash\":\"c6fa4c236f59020ec8ffde22f85a78e7f256e94cd975eb5199a4a5cc73e26e4a\", \"keypath\":\"m/44'/0'/0'/1/7\"}]}";
    char pubkey_1_input[] =
        "02721be181276eebdc4dd29dce180afa7c6a8199fb5f4c09f2e03b8e4193f22ce5";

    /*
      raw_tx = 0100000001e4b8a097d6d5cd351f69d9099e277b8a1c39a219991a4e5f9f86805faf649899010000001976a91488e6399fab42b2ea637da283dd87e70f4862e10c88acffffffff0298080000000000001976a91452922e52d08a2c1f1e4120803e56363fd7a8195188acb83d0000000000001976a914fd342347278e14013d17d53ed3c4aa7bf27eceb788ac0000000001000000
      sha256(sha256(hex2byte(raw_tx))) = c6fa4c236f59020ec8ffde22f85a78e7f256e94cd975eb5199a4a5cc73e26e4a
    */

    char two_inputs[] =
        "{\"meta\":\"_meta_data_\", \"data\":[{\"hash\":\"c12d791451bb41fd4b5145bcef25f794ca33c0cf4fe9d24f956086c5aa858a9d\", \"keypath\":\"m/44'/0'/0'/1/8\"},{\"hash\":\"3dfc3b1ed349e9b361b31c706fbf055ebf46ae725740f6739e2dfa87d2a98790\", \"keypath\":\"m/44'/0'/0'/0/5\"}]}";
    char pubkey_2_input_1[] =
        "0367d99d26d908bc11adaf05e1c18072b67e825f27dfadd504b013bafaa0f364a6";
    char pubkey_2_input_2[] =
        "032ab901fe42a05e970e6d5c701b4d7a6db33b0fa7daaaa709ebe755daf9dfe0ec";
    /*
      raw_tx = 01000000029ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f000000001976a91452922e52d08a2c1f1e4120803e56363fd7a8195188acffffffff9ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f0100000000ffffffff01c8000000000000001976a914584495bb22f4cb66cd47f2255cbc7178c6f3caeb88ac0000000001000000
      sha256(sha256(hex2byte(raw_tx))) = 3dfc3b1ed349e9b361b31c706fbf055ebf46ae725740f6739e2dfa87d2a98790

      raw_tx = 01000000029ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f0000000000ffffffff9ecf1f09baed314ee1cc37ee2236dca5f71f7dddc83a2a1b6358e739ac68c43f010000001976a914fd342347278e14013d17d53ed3c4aa7bf27eceb788acffffffff01c8000000000000001976a914584495bb22f4cb66cd47f2255cbc7178c6f3caeb88ac0000000001000000
      sha256(sha256(hex2byte(raw_tx))) = c12d791451bb41fd4b5145bcef25f794ca33c0cf4fe9d24f956086c5aa858a9d
    */

    int i;
    char hashstr[] =
        "{\"hash\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\", \"keypath\":\"m/100203p/45p/0/100\"}";
    char hashstart[] =
        "{\"meta\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\", \"checkpub\":[{\"pubkey\":\"000000000000000000000000000000000000000000000000000000000000000000\", \"keypath\":\"m/100203p/45p/0/100\"}], \"data\": [";
    char maxhashes[COMMANDER_REPORT_SIZE];
    char hashoverflow[COMMANDER_REPORT_SIZE];

    memset(hashoverflow, 0, sizeof(hashoverflow));
    memset(maxhashes, 0, sizeof(maxhashes));
    strcat(maxhashes, hashstart);
    strcat(maxhashes, hashstr);
    i = 1;
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

    char checkpub[] =
        "{\"meta\":\"<<meta data here>>\", \"data\": [{\"hash\":\"c6fa4c236f59020ec8ffde22f85a78e7f256e94cd975eb5199a4a5cc73e26e4a\", \"keypath\":\"m/44p\"},{\"hash\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\", \"keypath\":\"m/44p\"}], \"checkpub\":[{\"pubkey\":\"000000000000000000000000000000000000000000000000000000000000000000\", \"keypath\":\"m/44p/0p/0p/1/8\"},{\"pubkey\":\"032ab901fe42a05e970e6d5c701b4d7a6db33b0fa7daaaa709ebe755daf9dfe0ec\", \"keypath\":\"m/44p/0p/0p/1/8\"}]}";
    char check_1[] =
        "\"pubkey\":\"000000000000000000000000000000000000000000000000000000000000000000\", \"present\":false";
    char check_2[] =
        "\"pubkey\":\"032ab901fe42a05e970e6d5c701b4d7a6db33b0fa7daaaa709ebe755daf9dfe0ec\", \"present\":true";
    char check_sig_1[] =
        "72b2aa04281c7c2d79cb6e08168865fcd492d4d2d36acb3e46a185368c9ee00c1cbae958a8092a3689088d05ec5c0f58db65612f7bf4b34b0a9b3a34af9ad8be";
    char check_sig_2[] =
        "1ce2c6e97a86399417a782b9fc7b926b7d58e309adf49e86380ebc02fd3823ad2fa595eb18178f062c2cba1d252992622c5bde536de4b09e52976a0eeedeac01";
    char check_pubkey[] =
        "02793907771bab33d3fa7e4d7ee7c355067a623265926c46fc433a83c11dceb29e";

    char checkpub_wrong_addr_len[] =
        "{\"meta\":\"<<meta data here>>\", \"data\": [{\"hash\":\"c6fa4c236f59020ec8ffde22f85a78e7f256e94cd975eb5199a4a5cc73e26e4a\", \"keypath\":\"m/44p\"},{\"hash\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\", \"keypath\":\"m/44p\"}], \"checkpub\":[{\"pubkey\":\"00\", \"keypath\":\"m/44p/0p/0p/1/8\"},{\"pubkey\":\"032ab901fe42a05e970e6d5c701b4d7a6db33b0fa7daaaa709ebe755daf9dfe0ec\", \"keypath\":\"m/44p/0p/0p/1/8\"}]}";

    char checkpub_missing_parameter[] =
        "{\"meta\":\"<<meta data here>>\", \"data\": [{\"hash\":\"c6fa4c236f59020ec8ffde22f85a78e7f256e94cd975eb5199a4a5cc73e26e4a\", \"keypath\":\"m/44p\"},{\"hash\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\", \"keypath\":\"m/44p\"}], \"checkpub\":[{\"pubkey\":\"032ab901fe42a05e970e6d5c701b4d7a6db33b0fa7daaaa709ebe755daf9dfe0ec\"}]}";


    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    // seed
    char seed[] =
        "{\"source\":\"xprv9s21ZrQH143K3URucR3Zd2rRJBGGQsNFEo3Ld3JtTeUAQARegm573eJiNsAjGsyAj3h9roseS7GA7Y3dcub1pLpQD3eud2XzkoCoFpYBLF3\", \"filename\":\"s.pdf\"}";
    api_format_send_cmd(cmd_str(CMD_seed), seed, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));


    // missing parameters
    api_format_send_cmd(cmd_str(CMD_sign), checkpub_missing_parameter, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_sign),
                        "{\"data\":[{\"keypath\":\"m/\"}]}",
                        PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_sign),
                        "{\"data\":[{\"hash\":\"empty\"}]}",
                        PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    // data is not an array
    api_format_send_cmd(cmd_str(CMD_sign),
                        "{\"data\":{\"hash\":\"empty\"}}",
                        PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    // sign max number of hashes per sign command
    api_format_send_cmd(cmd_str(CMD_sign), maxhashes, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));

    api_format_send_cmd(cmd_str(CMD_sign), "", PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    // sign 1 more than max number of hashes per sign command
    api_format_send_cmd(cmd_str(CMD_sign), hashoverflow, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));

    api_format_send_cmd(cmd_str(CMD_sign), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_REPORT_BUF));

    // sign using one input
    api_format_send_cmd(cmd_str(CMD_sign), one_input, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        u_assert_str_has(utils_read_decrypted_report(), "_meta_data_");
        u_assert_str_has(utils_read_decrypted_report(), "m/44'/0'/0'/1/7");
        u_assert_str_has_not(utils_read_decrypted_report(), cmd_str(CMD_pubkey));
    }

    api_format_send_cmd(cmd_str(CMD_sign), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_pubkey));
    u_assert_str_has(utils_read_decrypted_report(), hash_1_input);
    u_assert_str_has(utils_read_decrypted_report(), pubkey_1_input);

    // sign using two inputs
    api_format_send_cmd(cmd_str(CMD_sign), two_inputs, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        u_assert_str_has(utils_read_decrypted_report(), "_meta_data_");
        u_assert_str_has(utils_read_decrypted_report(), "m/44'/0'/0'/1/8");
        u_assert_str_has_not(utils_read_decrypted_report(), cmd_str(CMD_pubkey));
    }

    api_format_send_cmd(cmd_str(CMD_sign), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_sign));
    u_assert_str_has(utils_read_decrypted_report(), hash_2_input_1);
    u_assert_str_has(utils_read_decrypted_report(), hash_2_input_2);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_pubkey));
    u_assert_str_has(utils_read_decrypted_report(), pubkey_2_input_1);
    u_assert_str_has(utils_read_decrypted_report(), pubkey_2_input_2);


    // test checkpub
    api_format_send_cmd(cmd_str(CMD_sign), checkpub, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        u_assert_str_has(utils_read_decrypted_report(), "\"meta\":");
        u_assert_str_has(utils_read_decrypted_report(), check_1);
        u_assert_str_has(utils_read_decrypted_report(), check_2);
    }

    api_format_send_cmd(cmd_str(CMD_sign), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_sign));
    u_assert_str_has(utils_read_decrypted_report(), check_sig_1);
    u_assert_str_has(utils_read_decrypted_report(), check_sig_2);
    u_assert_str_has(utils_read_decrypted_report(), check_pubkey);

    api_format_send_cmd(cmd_str(CMD_sign), checkpub_wrong_addr_len, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SIGN_PUBKEY_LEN));

    api_format_send_cmd(cmd_str(CMD_sign), checkpub_wrong_addr_len, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SIGN_PUBKEY_LEN));


    // lock to get TFA PINs
    int pin_err_count = 0;
    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_lock), PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    // sign using one input
    api_format_send_cmd(cmd_str(CMD_sign), one_input, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        u_assert_str_has(utils_read_decrypted_report(), "_meta_data_");
        u_assert_str_has(utils_read_decrypted_report(), "m/44'/0'/0'/1/7");
        u_assert_str_has_not(utils_read_decrypted_report(), cmd_str(CMD_pubkey));
        u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_pin));
    }

    // skip sending pin
    api_format_send_cmd(cmd_str(CMD_sign), one_input, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SIGN_TFA_PIN));
    if (TEST_LIVE_DEVICE) {
        pin_err_count++;
    }

    // send wrong pin
    api_format_send_cmd(cmd_str(CMD_sign), one_input, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        u_assert_str_has(utils_read_decrypted_report(), "_meta_data_");
        u_assert_str_has(utils_read_decrypted_report(), "m/44'/0'/0'/1/7");
        u_assert_str_has_not(utils_read_decrypted_report(), cmd_str(CMD_pubkey));
        u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_pin));
    }

    api_format_send_cmd(cmd_str(CMD_sign), "{\"pin\":\"000\"}", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SIGN_TFA_PIN));

    // send correct pin
    api_format_send_cmd(cmd_str(CMD_sign), one_input, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        u_assert_str_has(utils_read_decrypted_report(), "_meta_data_");
        u_assert_str_has(utils_read_decrypted_report(), "m/44'/0'/0'/1/7");
        u_assert_str_has_not(utils_read_decrypted_report(), cmd_str(CMD_pubkey));
        u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_pin));
    } else {
        pin_err_count++;
    }

    api_format_send_cmd(cmd_str(CMD_sign), "{\"pin\":\"0001\"}", PASSWORD_STAND);
    if (!TEST_LIVE_DEVICE) {
        u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
        u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_sign));
        u_assert_str_has(utils_read_decrypted_report(), hash_1_input);
        u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_pubkey));
        u_assert_str_has(utils_read_decrypted_report(), pubkey_1_input);
    } else {
        pin_err_count++;
    }


    // sign using two inputs
    api_format_send_cmd(cmd_str(CMD_sign), two_inputs, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));
    if (!TEST_LIVE_DEVICE) {
        u_assert_str_has(utils_read_decrypted_report(), "_meta_data_");
        u_assert_str_has(utils_read_decrypted_report(), "m/44'/0'/0'/1/8");
        u_assert_str_has_not(utils_read_decrypted_report(), cmd_str(CMD_pubkey));
    }

    // send correct pin
    api_format_send_cmd(cmd_str(CMD_sign), "{\"pin\":\"0001\"}", PASSWORD_STAND);
    if (!TEST_LIVE_DEVICE) {
        u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
        u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_sign));
        u_assert_str_has(utils_read_decrypted_report(), hash_2_input_1);
        u_assert_str_has(utils_read_decrypted_report(), hash_2_input_2);
        u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_pubkey));
        u_assert_str_has(utils_read_decrypted_report(), pubkey_2_input_1);
        u_assert_str_has(utils_read_decrypted_report(), pubkey_2_input_2);
    } else {
        pin_err_count++;
    }

    for (; pin_err_count < COMMANDER_MAX_ATTEMPTS - 1; pin_err_count++) {
        api_format_send_cmd(cmd_str(CMD_sign), one_input, PASSWORD_STAND);
        u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));
        api_format_send_cmd(cmd_str(CMD_sign), "{\"pin\":\"000\"}", PASSWORD_STAND);
        u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_SIGN_TFA_PIN));
        u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_WARN_RESET));
    }

    api_format_send_cmd(cmd_str(CMD_sign), one_input, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), cmd_str(CMD_echo));
    api_format_send_cmd(cmd_str(CMD_sign), "{\"pin\":\"000\"}", PASSWORD_STAND);
    if (!TEST_LIVE_DEVICE) {
        u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_RESET));
    }
    api_format_send_cmd(cmd_str(CMD_device), attr_str(ATTR_lock), PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_NO_PASSWORD));
}

static void tests_sign_recoverable_api(void)
{
	// m/44'/0'/0'/1/7
	char command[] = "{\"recoverable\":\"yes\", \"type\": \"meta\", \"meta\" : \"OriginalTranction\", \"data\" : [ { \"hash\" : \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\", \"keypath\" : \"m/44'/60'/0'/0'/0\" } ], \"checkpub\" : [] }";
	
	// Reset and seed device
	api_reset_device();
	
	api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE);
	u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
	
	// seed
	char seed[] =
	"{\"source\":\"xprv9s21ZrQH143K3URucR3Zd2rRJBGGQsNFEo3Ld3JtTeUAQARegm573eJiNsAjGsyAj3h9roseS7GA7Y3dcub1pLpQD3eud2XzkoCoFpYBLF3\"}";
	api_format_send_cmd(cmd_str(CMD_seed), seed, PASSWORD_STAND);
	u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
	
	// first get public key which we'll compare to after recovery and signature verification
//	"{\"xpub\":\"" + _keyPath + "\"}"
	api_format_send_cmd(cmd_str(CMD_xpub), "m/44'/60'/0'/0'/0", PASSWORD_STAND);
	u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
	u_assert_str_has(utils_read_decrypted_report(), "xpub6H6bcsTDcTChHZYrTEZLUCxcPhD9cU5emUf2BP32M2hdyf157G6k6MTBYrYwQudwDB2fDWec5qFY799JUQqMdgi5nvYwJK5TAaiAz7yhyL8");
	
	api_format_send_cmd(cmd_str(CMD_sign), command, PASSWORD_STAND);
	u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
	
	api_format_send_cmd(cmd_str(CMD_sign), "", PASSWORD_STAND);
	u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
	// signature
	char expected_signature[131] = "5582ed262db59e47d4f35f35432e465f911f5ceda3fdc12f4ad6ff7f5d2104777aa522f24101bf7b336338d097e019bfedff636a1d6ab95ba6d73820349ff49e01";
	u_assert_str_has(utils_read_decrypted_report(), expected_signature);
	
	char expected_publickey[129] = "751a90b67a9970fd59ef34689332ec4e6c4d0daeeb98d8bafc5d15985ea25da0311e0906c9bfcddf22f32801929a8ff59d1a6a7ec5f73447f399985409af5489";
	u_assert_str_has(utils_read_decrypted_report(), expected_publickey);
	
	// manually recover public key from signature and verify match
	uint8_t sig[65];
	memcpy(sig,
		   utils_hex_to_uint8(expected_signature),
		   65);
	uint8_t hash[32];
	memcpy(hash,
		   utils_hex_to_uint8("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		   32);
	uint8_t public_key[64];
	int res = ecc_recover(sig, hash, public_key);
	u_assert_int_eq(res, 0);
	u_assert_mem_eq(utils_hex_to_uint8(expected_publickey), public_key, 64);
	
}


// test vectors generated from Python 2.7 code using aes, base64, and hashlib imports
static void tests_aes_cbc(void)
{
    const char **plainp, **cipherp;

    char encrypt[] = "{\"type\":\"encrypt\", \"data\":\"";
    char decrypt[] = "{\"type\":\"decrypt\", \"data\":\"";
    char password[] = "{\"type\":\"password\", \"data\":\"passwordpassword\"}";
    char verify[] = "{\"type\":\"verify\", \"data\":\"passwordpassword\"}";
    char xpub[] = "{\"type\":\"xpub\", \"data\":\"m/0'\"}";
    char enc[COMMANDER_REPORT_SIZE * 2], dec[COMMANDER_REPORT_SIZE * 2];
    memset(enc, 0, sizeof(enc));
    memset(dec, 0, sizeof(dec));

    static const char *aes_vector[] = {
        // plain                cipher (for 'passwordpassword')
        "digital bitbox", "mheIJghfKiPxQpvqbbRCZnTkbMd+BdRf+1jDAjk9h2Y=",
        "Satoshi Nakamoto", "28XHUwA+/5zHeSIxt1Ioaifl/BqWsTow1hrzJJ7p91EgYbw6MwzFMlLOWq22fUsw",
        "All those moments will be lost in time, like tears in rain. Time to die...", "qjfyIWCoY8caehZFoZStmtDz6FaKYCaCrJXyiF6I2LwnLPVV9oGv9NtJ7aVXAICeP0Q2Agh0oPlbBLKfjkdtZGuwV/tya7KcIl1ieC/276JwRl2+XdkK3uBb2Yrljl4T",
        "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!", "biR4Ce1vnvrYAOQRwO+bW4aXiySH4plHVc9LlN8hJAb/q6Tw0x6aI+A7EeOF5a11EPTjJ454nREZ9S4nIBwlGDto2GrEq+TwQOpKb/YU1VxeGGlFLg8comVnVSPmNQ1WNX/E5bnNX8osgF69QFxOgaPzfLdKGr4isUBVO3BlOPV4oUmIUc7+DC5PwabWV4XrxLQzzw79KRxL3iPk4Tbk3CDxDBgE5Z7HlvZfTM5J9d7majdQTMtHYP7d1MJZblyTkB1R7DemQhf7xHllkSXwHattstz/d1NmgGQXHlISoPs=",
        0, 0,
    };

    char seed[] =
        "{\"source\":\"xprv9s21ZrQH143K2MkmL8hdyZk5uwTPEqkwS72jXDt5DGRtUVrfYiAvAnGmxmP3J5Z3BG5uQcy5UYUMDsqisyXEDNCG2uzixsckhnfCrJxKVme\", \"filename\":\"x.pdf\"}";

    api_reset_device();

    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_aes256cbc), verify, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
    if (!TEST_LIVE_DEVICE) {
        yajl_val json_node = yajl_tree_parse(utils_read_decrypted_report(), NULL, 0);
        const char *ciphertext_path[] = { cmd_str(CMD_aes256cbc), (const char *) 0 };
        const char *ciphertext = YAJL_GET_STRING(yajl_tree_get(json_node, ciphertext_path,
                                 yajl_t_string));
        int dlen;
        char *d = aes_cbc_b64_decrypt((const unsigned char *)ciphertext, strlens(ciphertext),
                                      &dlen, PASSWORD_VERIFY);
        u_assert_str_eq(d, "passwordpassword");
        free(d);
        yajl_tree_free(json_node);
    }

    memcpy(dec, decrypt, strlens(decrypt));
    strcat(dec, "password not set error\"}");
    api_format_send_cmd(cmd_str(CMD_aes256cbc), dec, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_NO_PASSWORD));

    api_format_send_cmd(cmd_str(CMD_aes256cbc), xpub, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_KEY_MASTER));

    api_format_send_cmd(cmd_str(CMD_seed), seed, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_aes256cbc), xpub, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_aes256cbc), password, PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_aes256cbc), "type", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_aes256cbc), "", PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));


    memcpy(enc, encrypt, strlens(encrypt));
    memset(enc + strlens(encrypt), 'a', AES_DATA_LEN_MAX + 1);
    strcat(enc, "\"}");
    api_format_send_cmd(cmd_str(CMD_aes256cbc), enc, PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_DATA_LEN));

    api_format_send_cmd(cmd_str(CMD_aes256cbc), "{\"type\":\"\", \"data\":\"\"}",
                        PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_INVALID_CMD));

    api_format_send_cmd(cmd_str(CMD_aes256cbc), "{\"type\":\"encrypt\", \"data\":\"\"}",
                        PASSWORD_STAND);
    u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

    api_format_send_cmd(cmd_str(CMD_aes256cbc), "{\"type\":\"decrypt\", \"data\":\"\"}",
                        PASSWORD_STAND);
    u_assert_str_has(utils_read_decrypted_report(), flag_msg(DBB_ERR_IO_DECRYPT));

    plainp = aes_vector;
    cipherp = aes_vector + 1;
    while (*plainp && *cipherp) {

        // check decryption
        memset(dec, 0, sizeof(dec));
        memcpy(dec, decrypt, strlens(decrypt));
        memcpy(dec + strlens(decrypt), *cipherp, strlens(*cipherp));
        strcat(dec, "\"}");

        api_format_send_cmd(cmd_str(CMD_aes256cbc), dec, PASSWORD_STAND);
        u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
        u_assert_mem_eq(*plainp, api_read_value(CMD_aes256cbc), strlens(*plainp));

        // check encryption by encrypting then decrypting
        memset(enc, 0, sizeof(enc));
        memcpy(enc, encrypt, strlens(encrypt));
        memcpy(enc + strlens(encrypt), *plainp, strlens(*plainp));
        strcat(enc, "\"}");

        api_format_send_cmd(cmd_str(CMD_aes256cbc), enc, PASSWORD_STAND);
        u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));

        const char *e = api_read_value(CMD_aes256cbc);

        memset(dec, 0, sizeof(dec));
        memcpy(dec, decrypt, strlens(decrypt));
        memcpy(dec + strlens(decrypt), e, strlens(e));
        strcat(dec, "\"}");

        api_format_send_cmd(cmd_str(CMD_aes256cbc), dec, PASSWORD_STAND);
        u_assert_str_has_not(utils_read_decrypted_report(), attr_str(ATTR_error));
        u_assert_mem_eq(*plainp, api_read_value(CMD_aes256cbc), strlens(*plainp));

        plainp += 2;
        cipherp += 2;
    }
}


static void run_utests(void)
{
    u_run_test(tests_echo_tfa);
    u_run_test(tests_aes_cbc);
    u_run_test(tests_name);
    u_run_test(tests_password);
    u_run_test(tests_random);
    u_run_test(tests_sign);
    u_run_test(tests_device);
    u_run_test(tests_input);
    u_run_test(tests_seed_xpub_backup);

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
    random_init();
    __stack_chk_guard = random_uint32(0);
    ecc_context_init();
    memory_setup();
    memory_setup(); // run twice
    printf("\n\nInternal API Result:\n");
    run_utests();

#ifndef CONTINUOUS_INTEGRATION
    // Live test of the HID API
    // Requires the hidapi library to be installed:
    //     http://www.signal11.us/oss/hidapi/
    TEST_LIVE_DEVICE = 1;
    memory_write_aeskey(tests_pwd, strlens(tests_pwd), PASSWORD_STAND);
    memory_write_aeskey(reset_pwd, strlens(reset_pwd), PASSWORD_RESET);
    if (api_hid_init() == DBB_ERROR) {
        printf("\n\nNot testing HID API. A device is not connected.\n\n");
    } else {
        printf("\n\nHID API Result:\n");
        run_utests();
    }
#endif

    ecc_context_destroy();
    return U_TESTS_FAIL;
}
