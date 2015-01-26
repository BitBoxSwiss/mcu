/*

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

#include "utils.h"
#include "random.h"
#include "memory.h"
#include "commander.h"


void usage(char * argv[])
{
    printf("\nThis function provides a command line interface to the Digital Bitbox code.\n");
    
    printf("  Usage:\n\t%s json_commands\n\n", argv[0]);
    printf("  Example:\n\t./tests_cmdline \"{ \\\"seed\\\":{\\\"wallet\\\":\\\"bip32\\\"},  "
           "\\\"sign\\\":{\\\"wallet\\\":\\\"bip32\\\", \\\"data\\\":\\\"Hello.\\\", "
           "\\\"encoding\\\":\\\"message\\\", \\\"keypath\\\":\\\"m/44'/0'/1'/0/1\\\"} }\"\n\n" );
    
    printf( "See the online API documentation for a list of JSON commands at\ndigitalbitbox.com. "
            "Multiple commands can be sent within a single\nJSON object. This is shown in the "
            "example where a BIP32-type wallet\nis first generated and then used to sign a message.\n\n\n");
}


int main ( int argc, char *argv[] )
{
    if (argc != 2) {
        usage(argv);
    } else {
        rand_init(); 
        memory_erase();
        commander("{\"password\":\"passwordpassword\"}" ); // A password is required before sending commands.
        send_encrypted_cmd(argv[1]); 
    }
    return 0;
}
