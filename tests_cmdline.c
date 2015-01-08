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
#include <unistd.h>
#include <stdlib.h>

#include "utils.h"
#include "random.h"
#include "memory.h"
#include "commander.h"


extern const char * CMD_STR[];

void usage(char * argv[])
{
    printf( "\nThis function provides a command line interface to the Digital Bitbox code.\n" );
    printf( "  Usage:\n\t%s json_commands\n\n", argv[0] );
    printf( "  Example:\n\t./tests_cmdline \"{ \\\"seed\\\":{\\\"wallet\\\":\\\"bip32\\\"},  \\\"sign\\\":{\\\"wallet\\\":\\\"bip32\\\", \\\"message\\\":\\\"Hello.\\\", \\\"encoding\\\":\\\"message\\\", \\\"keypath\\\":\\\"m/44'/0'/1'/0/1\\\"} }\"\n\n" );
    printf( "See the online API documentation for a list of JSON commands at\ndigitalbitbox.com. Multiple commands can be sent within a single\nJSON object. This is shown in the example where a BIP32-type wallet\nis first generated and then used to sign a message.\n\n\n" );
}


void print_report( const char * report )
{
    int decrypt_len, r, i;
    jsmntok_t json_token[MAX_TOKENS];
    r = jsmn_parse_init(report, strlen(report), json_token, MAX_TOKENS);
     
    if (r < 0) {
        printf("Failed to parse report: %s : %s\n", CMD_STR[CMD_ciphertext_],report);
        return;
    }
    
    printf("\n\nReport:     \t%s    \n",report);
    
    for (i = 0; i < r; i++) {
        if (token_equals(report, &json_token[i], CMD_STR[CMD_ciphertext_]) == 0 ) {
            int len = json_token[i+1].end-json_token[i+1].start;
            char cipher[len+1];
            memcpy( cipher, report + json_token[i+1].start, len );
            cipher[len] = '\0';
            char * dec = aes_cbc_b64_decrypt( (unsigned char*)cipher, strlen(cipher), memory_aeskey_read(), &decrypt_len );
            printf("ciphertext:\t%.*s\n\n",decrypt_len,dec);
            free( dec );
            break;
        }
    }
}


void send_encrypted_cmd(const char * instruction)
{
    int encrypt_len;
    char * enc = aes_cbc_b64_encrypt( (unsigned char*)instruction, strlen(instruction), memory_aeskey_read(), &encrypt_len );
    commander( enc );
    free( enc ); 
    print_report(hid_report);
}


int main ( int argc, char *argv[] )
{
    if ( argc != 2 )
    {
        usage(argv);
    }
    else 
    {
        rand_init(); 
        memory_setup();
        commander("{\"password\":\"passwordpassword\"}" ); // A password is required before sending commands.
        send_encrypted_cmd(argv[1]); 
    }
    return 0;
}
