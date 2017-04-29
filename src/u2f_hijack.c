/*

 The MIT License (MIT)

 Copyright (c) 2017 Douglas J. Bakkum, Shift Devices AG

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

#include "u2f_hijack.h"
#include "u2f_device.h"
#include "u2f/u2f.h"
#include "commander.h"
#include "wallet.h"
#include "memory.h"
#include "touch.h"
#include "bip32.h"
#include "flags.h"
#include "ecc.h"
#include "led.h"


#if (MEM_PAGE_LEN != U2F_NONCE_LENGTH) || (U2F_HIJACK_REQ_KEYPATH_MAX_LEN <= U2F_HIJACK_ETH_KEYPATH_LEN)
#error "Incorrect macro values for u2f_hijack"
#endif


const uint8_t U2F_HIJACK_CODE[] = {57, 55, 173, 209, 178, 255, 144, 175, 24, 190, 240, 197, 183, 84, 22, 170, 58, 118, 133, 98, 243, 145, 238, 136, 137, 134, 248, 90, 247, 202, 114, 148};// Corresponds to a U2F client challenge filled with `0xdb` (refer to the MEW JavaScript integration)

static bool U2F_HIJACK_UNLOCKED = false;// Correct (session) password received


void u2f_hijack(const U2F_REQ_HIJACK *req)
{
    // TODO - add unit testing

    if (req->mode == U2F_HIJACK_ETH_MODE) {
        char keypath[64];
        const uint32_t ctr = memory_u2f_count_iter();
        uint8_t buf[sizeof(U2F_RESP_HIJACK)];
        U2F_RESP_HIJACK *resp = (U2F_RESP_HIJACK *)&buf;
        HDNode node;

        memset(buf, 0, sizeof(buf));

        resp->flags = 0;
        resp->ctr[0] = (ctr >> 24) & 0xff;
        resp->ctr[1] = (ctr >> 16) & 0xff;
        resp->ctr[2] = (ctr >> 8) & 0xff;
        resp->ctr[3] = ctr & 0xff;

        // Append success bytes so that response gets through U2F client code.
        // Otherwise, the client will resend sign requests until timing out.
        // Errors handled instead using resp->status.
        resp->sw1 = 0x90;
        resp->sw2 = 0x00;

        if (memory_report_erased()) {
            resp->status = U2F_SW_DATA_INVALID;
            goto exit;
        }

        if (!U2F_HIJACK_UNLOCKED) {
            if (memcmp(memory_report_aeskey(PASSWORD_STAND), req->password, MEM_PAGE_LEN) != 0) {
                memory_access_err_count(DBB_ACCESS_ITERATE);
                resp->status = U2F_SW_WRONG_DATA;
                goto exit;
            } else {
                memory_access_err_count(DBB_ACCESS_INITIALIZE);
                U2F_HIJACK_UNLOCKED = true;
            }
        }

        if (req->keypathlen > U2F_HIJACK_REQ_KEYPATH_MAX_LEN) {
            resp->status = U2F_SW_WRONG_DATA;
            goto exit;
        }

        memset(keypath, 0, sizeof(keypath));
        memcpy(keypath, req->keypath, req->keypathlen);

        if (strncmp(keypath, U2F_HIJACK_ETH_KEYPATH, U2F_HIJACK_ETH_KEYPATH_LEN) != 0) {
            resp->status = U2F_SW_WRONG_DATA;
            goto exit;
        }

        if (wallet_seeded() != DBB_OK) {
            resp->status = U2F_SW_DATA_INVALID;
            goto exit;
        }

        if (wallet_generate_key(&node, keypath, wallet_get_master(),
                                wallet_get_chaincode()) != DBB_OK) {
            resp->status = U2F_SW_DATA_INVALID;
            goto exit;
        }

        if (req->op == U2F_HIJACK_OP_XPUB) {
            uint8_t public_key[65];
            led_blink();
            bitcoin_ecc.ecc_get_public_key65(node.private_key, public_key, ECC_SECP256k1);
            // Be sure resp->data is < U2F_HIJACK_RESP_DATA_MAX_LEN
            memcpy(resp->data, public_key, sizeof(public_key));
            memcpy(resp->data + sizeof(public_key), node.chain_code, 32);
        } else if (req->op == U2F_HIJACK_OP_SIGN) {
            char *echo;
            int32_t echo_len;
            uint8_t recid;
            uint8_t sig[64];
            if (touch_button_press(DBB_TOUCH_LONG_BLINK) != DBB_TOUCHED) {
                resp->status = U2F_SW_CONDITIONS_NOT_SATISFIED;
                goto exit;
            }
            if (bitcoin_ecc.ecc_sign_digest(node.private_key, req->data, sig, &recid,
                                            ECC_SECP256k1)) {
                resp->status = U2F_SW_WRONG_DATA;
                goto exit;
            }

            echo = aes_cbc_b64_encrypt((const unsigned char *)req->data,
                                       U2F_HIJACK_REQ_DATA_MAX_LEN,
                                       (int *)&echo_len,
                                       PASSWORD_VERIFY);

            if (!echo) {
                resp->status = U2F_SW_WRONG_DATA;
                goto exit;
            }

            // Be sure resp->data is < U2F_HIJACK_RESP_DATA_MAX_LEN
            if (sizeof(recid) + sizeof(sig) + sizeof(echo_len) + echo_len >
                    U2F_HIJACK_RESP_DATA_MAX_LEN) {
                free(echo);
                resp->status = U2F_SW_WRONG_DATA;
                goto exit;
            }
            memcpy(resp->data, &recid, sizeof(recid));
            memcpy(resp->data + sizeof(recid), sig, sizeof(sig));
            memcpy(resp->data + sizeof(recid) + sizeof(sig), &echo_len, sizeof(echo_len));
            memcpy(resp->data + sizeof(recid) + sizeof(sig) + sizeof(echo_len), echo, echo_len);
            free(echo);
        } else {
            resp->status = U2F_SW_WRONG_DATA;
            goto exit;
        }

        resp->status = U2F_SW_NO_ERROR;
    exit:
        u2f_send_message(buf, sizeof(U2F_RESP_HIJACK));
    }
}
