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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ecc.h"
#include "flags.h"
#include "utils.h"
#include "random.h"
#include "memory.h"
#include "yajl/src/api/yajl_tree.h"

#include "api.h"


static void usage(char *argv[])
{
    printf("\nExample code to run the Digital Bitbox MCU code.\n");
    printf("  Usage:\n\t%s json_commands\n\n", argv[0]);
    printf("  Example:\n\t./tests_cmdline '{ \"seed\":{\"source\":\"create\"} }'\n\n" );
    printf( "See the online API documentation for a list of JSON commands at\ndigitalbitbox.com.\n\n\n");
}


int main(int argc, char *argv[])
{
    if (argc != 2) {
        usage(argv);
    } else {
        random_init();
        memory_setup();
        ecc_context_init();

        TEST_LIVE_DEVICE = 1;
        memory_write_aeskey("0000", 4, PASSWORD_STAND);
        if (api_hid_init() == DBB_ERROR) {
            printf("\n\nA device is not connected.\n\n");
            return 1;
        }

        // A password is required before sending commands.
        //api_send_cmd("{\"password\":\"0000\"}", PASSWORD_NONE);

        // Send the command
        api_send_cmd(argv[1], PASSWORD_STAND);
        printf("%s\n", utils_read_decrypted_report());

        ecc_context_destroy();
    }
    return 0;
}

