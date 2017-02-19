// Copyright 2014 Google Inc. All rights reserved.
// Copyright 2017 Douglas J. Bakkum, Shift Devices AG
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd


// U2F register / sign compliance test.


#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>  // ntohl, htonl
#else
#include <arpa/inet.h>  // ntohl, htonl
#endif

#include "u2f/u2f_t.h"
#include "u2f/u2f_util_t.h"

#include "random.h"
#include "memory.h"
#include "utils.h"
#include "sha2.h"
#include "ecc.h"


static bool arg_hasButton = true;  // fob has button

struct U2Fob *device;

U2F_REGISTER_REQ regReq;
U2F_REGISTER_RESP regRsp;


static void WaitForUserPresence(struct U2Fob *dev, bool hasButton)
{
    char msg[1];
    U2Fob_close(dev);
    if (U2Fob_liveDeviceTesting()) {
        if (hasButton) {
            printf("Hit enter then touch the device button...");
        }
        if (scanf("%c", msg)) {
            (void) msg;
        }
    }
    CHECK_EQ(0, U2Fob_reopen(dev));
    CHECK_EQ(0, U2Fob_init(dev));
}


static void test_Version(void)
{
    char rsp[4096];
    size_t rsp_len;
    int res = U2Fob_apdu(device, 0, U2F_INS_VERSION, 0, 0, "", 0, rsp, &rsp_len);
    if (res == 0x9000) {
        CHECK_EQ(0, strncmp("U2F_V2", rsp, rsp_len));
        return;
    }

    // Non-ISO 7816-4 compliant U2F_INS_VERSION "APDU" that includes Lc value 0,
    // for compatibility with older devices.
    uint8_t buf[4 + 3 + 2];
    buf[0] = 0;  // CLA
    buf[1] = U2F_INS_VERSION;  // INS
    buf[2] = 0;  // P1
    buf[3] = 0;  // P2
    buf[4] = 0;  // extended length
    buf[5] = 0;  // Lc = 0 (Not ISO 7816-4 compliant)
    buf[6] = 0;  // Lc = 0 (Not ISO 7816-4 compliant)
    buf[7] = 0;  // Le = 0
    buf[8] = 0;  // Le = 0
    CHECK_EQ(0x9000, U2Fob_exchange_apdu_buffer(device, buf, sizeof(buf), rsp, &rsp_len));
    CHECK_EQ(0, strncmp("U2F_V2", rsp, rsp_len));
}


static void test_UnknownINS(void)
{
    char rsp[4096];
    size_t rsp_len;
    CHECK_EQ(0x6D00, U2Fob_apdu(device, 0, 0 /* not U2F INS */,
                                0, 0, "", 0, rsp, &rsp_len));
    CHECK_EQ(rsp_len, 0);
}


static void test_BadCLA(void)
{
    char rsp[4096];
    size_t rsp_len;
    CHECK_EQ(0x6E00, U2Fob_apdu(device, 1 /* not U2F CLA, 0x00 */,
                                U2F_INS_VERSION, 0, 0, "abc", 3, rsp, &rsp_len));
    CHECK_EQ(rsp_len, 0);
}


static void test_WrongLength_U2F_VERSION(void)
{
    char rsp[4096];
    size_t rsp_len;
    // U2F_VERSION does not take any input.
    CHECK_EQ(0x6700, U2Fob_apdu(device, 0, U2F_INS_VERSION, 0, 0, "abc", 3, rsp, &rsp_len));
    CHECK_EQ(rsp_len, 0);
}


static void test_WrongLength_U2F_REGISTER(void)
{
    char rsp[4096];
    size_t rsp_len;
    // U2F_REGISTER does expect input.
    CHECK_EQ(0x6700, U2Fob_apdu(device, 0, U2F_INS_REGISTER, 0, 0, "abc", 3, rsp, &rsp_len));
    CHECK_EQ(rsp_len, 0);
}


static void test_Enroll(int expectedSW12)
{
    // pick random origin and challenge.
    for (size_t i = 0; i < sizeof(regReq.nonce); ++i) {
        regReq.nonce[i] = rand();
    }
    for (size_t i = 0; i < sizeof(regReq.appId); ++i) {
        regReq.appId[i] = rand();
    }

    uint64_t t = 0;
    U2Fob_deltaTime(&t);

    char rsp[4096];
    size_t rsp_len;
    char regReq_c[U2F_NONCE_SIZE + U2F_APPID_SIZE + 1];
    memset(regReq_c, 0, sizeof(regReq_c));
    memcpy(regReq_c, regReq.nonce, U2F_NONCE_SIZE);
    memcpy(regReq_c + U2F_NONCE_SIZE, regReq.appId, U2F_APPID_SIZE);
    CHECK_EQ(expectedSW12,
             U2Fob_apdu(device, 0, U2F_INS_REGISTER, U2F_AUTH_ENFORCE, 0,
                        regReq_c, sizeof(regReq), rsp, &rsp_len));

    if (expectedSW12 != 0x9000) {
        CHECK_EQ(rsp_len, 0);
        return;
    }

    CHECK_NE(rsp_len, 0);
    CHECK_LE(rsp_len, sizeof(U2F_REGISTER_RESP));

    memcpy(&regRsp, rsp, rsp_len);
    CHECK_EQ(regRsp.registerId, U2F_REGISTER_ID);
    CHECK_EQ(regRsp.pubKey.format, UNCOMPRESSED_POINT);

    printf("\x1b[34mEnroll: %lu bytes in %fs\x1b[0m\n", rsp_len, U2Fob_deltaTime(&t));

    // Check crypto of enroll response.
    char cert[MAX_CERT_SIZE];
    size_t cert_len;
    CHECK_EQ(getCertificate(regRsp, cert, &cert_len), true);
    printf("\x1b[34mCertificate: %lu %s\x1b[0m\n", cert_len,
           utils_uint8_to_hex((uint8_t *)cert, cert_len));

    char pk[P256_POINT_SIZE];
    size_t pk_len;
    CHECK_EQ(getSubjectPublicKey(cert, cert_len, pk, &pk_len), true);
    printf("\x1b[34mPublic key:  %lu %s\x1b[0m\n", pk_len, utils_uint8_to_hex((uint8_t *)pk,
            pk_len));
    CHECK_EQ(pk_len, P256_POINT_SIZE);

    char sig[MAX_ECDSA_SIG_SIZE];
    size_t sig_len;
    CHECK_EQ(getSignature(regRsp, sig, &sig_len), true);
    printf("\x1b[34mSignature:   %lu %s\x1b[0m\n", sig_len, utils_uint8_to_hex((uint8_t *)sig,
            sig_len));

    // Parse signature into two integers.
    uint8_t signature[64];
    CHECK_EQ(0, ecc_der_to_sig((uint8_t *)sig, sig_len, signature));

    // Compute hash.
    uint8_t hash[SHA256_BLOCK_LENGTH];
    uint8_t rfu = 0;
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, &rfu, sizeof(rfu));  // 0x00
    sha256_Update(&ctx, regReq.appId, sizeof(regReq.appId));  // O
    sha256_Update(&ctx, regReq.nonce, sizeof(regReq.nonce));  // d
    sha256_Update(&ctx, regRsp.keyHandleCertSig, regRsp.keyHandleLen); // hk
    sha256_Update(&ctx, (uint8_t *)&regRsp.pubKey, sizeof(regRsp.pubKey));  // pk
    sha256_Final(hash, &ctx);

    // Verify signature.
    CHECK_EQ(0, ecc_verify_digest((uint8_t *)pk + 1, hash, signature, ECC_SECP256r1));
}


// returns ctr
static uint32_t test_Sign(int expectedSW12, bool checkOnly)
{
    U2F_AUTHENTICATE_REQ authReq;

    // pick random challenge and use registered appId.
    for (size_t i = 0; i < sizeof(authReq.nonce); ++i) {
        authReq.nonce[i] = rand();
    }
    memcpy(authReq.appId, regReq.appId, sizeof(authReq.appId));
    authReq.keyHandleLen = regRsp.keyHandleLen;
    memcpy(authReq.keyHandle, regRsp.keyHandleCertSig, authReq.keyHandleLen);

    uint64_t t = 0;
    U2Fob_deltaTime(&t);

    char rsp[4096];
    size_t rsp_len;
    char authReq_c[U2F_NONCE_SIZE + U2F_APPID_SIZE + 1 + MAX_KH_SIZE + 1];
    memset(authReq_c, 0, sizeof(authReq_c));
    memcpy(authReq_c, authReq.nonce, U2F_NONCE_SIZE);
    memcpy(authReq_c + U2F_NONCE_SIZE, authReq.appId, U2F_APPID_SIZE);
    memcpy(authReq_c + U2F_NONCE_SIZE + U2F_APPID_SIZE, &authReq.keyHandleLen, 1);
    memcpy(authReq_c + U2F_NONCE_SIZE + U2F_APPID_SIZE + 1, authReq.keyHandle,
           authReq.keyHandleLen);

    CHECK_EQ(expectedSW12,
             U2Fob_apdu(device, 0, U2F_INS_AUTHENTICATE,
                        checkOnly ? U2F_AUTH_CHECK_ONLY : U2F_AUTH_ENFORCE, 0,
                        authReq_c, U2F_NONCE_SIZE + U2F_APPID_SIZE + 1 + authReq.keyHandleLen,
                        rsp, &rsp_len));

    if (expectedSW12 != 0x9000) {
        CHECK_EQ(rsp_len, 0);
        return 0;
    }

    CHECK_NE(rsp_len, 0);
    CHECK_LE(rsp_len, sizeof(U2F_AUTHENTICATE_RESP));

    U2F_AUTHENTICATE_RESP resp;
    memcpy(&resp, rsp, rsp_len);

    CHECK_EQ(resp.flags, 0x01);

    printf("\x1b[34mSign: %lu bytes in %fs\x1b[0m\n", rsp_len, U2Fob_deltaTime(&t));

    // Parse signature from authenticate response.
    uint8_t signature[64];
    CHECK_EQ(0, ecc_der_to_sig(resp.sig, rsp_len - sizeof(resp.flags) - sizeof(resp.ctr),
                               signature));

    // Compute hash.
    uint8_t hash[SHA256_BLOCK_LENGTH];
    SHA256_CTX ctx;
    sha256_Init(&ctx);

    sha256_Update(&ctx, regReq.appId, sizeof(regReq.appId));  // O
    sha256_Update(&ctx, &resp.flags, sizeof(resp.flags));  // T
    sha256_Update(&ctx, (uint8_t *)&resp.ctr, sizeof(resp.ctr));  // CTR
    sha256_Update(&ctx, authReq.nonce, sizeof(authReq.nonce));  // d
    sha256_Final(hash, &ctx);

    // Verify signature.
    CHECK_EQ(0, ecc_verify_digest((uint8_t *)&regRsp.pubKey + 1, hash, signature,
                                  ECC_SECP256r1));

    return ntohl(resp.ctr);
}


static void check_Compilation(void)
{
    // Couple of sanity checks.
    CHECK_EQ(sizeof(P256_POINT), 65);
    CHECK_EQ(sizeof(U2F_REGISTER_REQ), 64);
}


static void run_tests(void)
{
    // Start of tests
    //
    device = U2Fob_create();

    if (U2Fob_open(device) == 0) {
        CHECK_EQ(0, U2Fob_init(device));
        PASS(check_Compilation());
        PASS(test_Version());
        PASS(test_UnknownINS());
        PASS(test_WrongLength_U2F_VERSION());
        PASS(test_WrongLength_U2F_REGISTER());
        PASS(test_BadCLA());

        // Fob with button should need touch.
        if (U2Fob_liveDeviceTesting() && arg_hasButton) {
            // Timeout
            fprintf(stderr, "Wait for device timeout.\n");
            fflush(stderr);
            PASS(test_Enroll(0x6985));
        }
        WaitForUserPresence(device, arg_hasButton);
        PASS(test_Enroll(0x9000));

        // Fob with button should have consumed touch.
        if (U2Fob_liveDeviceTesting() && arg_hasButton) {
            // Timeout
            fprintf(stderr, "Wait for device timeout.\n");
            fflush(stderr);
            PASS(test_Sign(0x6985, false));
        }

        // Sign with check only should not produce signature.
        PASS(test_Sign(0x6985, true));

        // Sign with wrong key handle.
        regRsp.keyHandleCertSig[0] ^= 0x55;
        PASS(test_Sign(0x6a80, false));
        regRsp.keyHandleCertSig[0] ^= 0x55;

        // Sign with wrong app id.
        regReq.appId[0] ^= 0xaa;
        PASS(test_Sign(0x6a80, false));
        regReq.appId[0] ^= 0xaa;

        // Sign with check only should not produce signature.
        WaitForUserPresence(device, arg_hasButton);
        PASS(test_Sign(0x6985, true));

        uint32_t ctr1;
        PASS(ctr1 = test_Sign(0x9000, false));
        if (U2Fob_liveDeviceTesting()) {
            // Timeout
            fprintf(stderr, "Wait for device timeout.\n");
            fflush(stderr);
            PASS(test_Sign(0x6985, false));
        }

        WaitForUserPresence(device, arg_hasButton);

        uint32_t ctr2;
        PASS(ctr2 = test_Sign(0x9000, false));

        // Ctr should have incremented by 1.
        CHECK_EQ(ctr2, ctr1 + 1);
    } else {
        printf("\n\nNot testing HID API. A device is not connected.\n\n");
        return;
    }

    U2Fob_destroy(device);
    return;
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

    srand((unsigned int) time(NULL));

    // Test the C code API
    U2Fob_testLiveDevice(0);
    random_init();
    __stack_chk_guard = random_uint32(0);
    ecc_context_init();
    memory_setup();
    memory_setup(); // run twice
    printf("\n\nInternal API Result:\n");
    run_tests();
    ecc_context_destroy();

    // Live test of the HID API
#ifndef CONTINUOUS_INTEGRATION
    U2Fob_testLiveDevice(1);
    printf("\n\nHID API Result:\n");
    run_tests();
#endif

    printf("\nALL TESTS PASSED\n\n");
    return 0;
}

