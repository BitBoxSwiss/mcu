/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */
/* Copyright 2015, Douglas J Bakkum - removed non secp256k1 curves; added supporting functions */

#ifndef _MICRO_ECC_H_
#define _MICRO_ECC_H_

#include <stdint.h>

/* Platform selection options.
If uECC_PLATFORM is not defined, the code will try to guess it based on compiler macros.
Possible values for uECC_PLATFORM are defined below: */
#define uECC_arch_other 0
#define uECC_x86        1
#define uECC_x86_64     2
#define uECC_arm        3
#define uECC_arm_thumb  4
#define uECC_avr        5
#define uECC_arm_thumb2 6

/* Inline assembly options.
uECC_asm_none  - Use standard C99 only.
uECC_asm_small - Use GCC inline assembly for the target platform (if available), optimized for minimum size.
uECC_asm_fast  - Use GCC inline assembly optimized for maximum speed. */
#define uECC_asm_none  0
#define uECC_asm_small 1
#define uECC_asm_fast  2
#define uECC_ASM uECC_asm_fast

/* uECC_SQUARE_FUNC - If enabled (defined as nonzero), this will cause a specific function to be used for (scalar) squaring
    instead of the generic multiplication function. This will make things faster by about 8% but increases the code size. */
#define uECC_SQUARE_FUNC 1

#define uECC_secp256k1 4
#define uECC_CURVE uECC_secp256k1
#define uECC_WORD_SIZE 4
#define uECC_BYTES  32

#define uECC_CONCAT1(a, b) a##b
#define uECC_CONCAT(a, b) uECC_CONCAT1(a, b)


// Generate an ECDSA signature for a given hash value.
// Returns 0 always.
int uECC_sign_digest(const uint8_t p_privateKey[uECC_BYTES],
                     const uint8_t p_hash[uECC_BYTES],
                     uint8_t p_signature[uECC_BYTES * 2]);

// Performs sha256 hash on msg before signing.
// Returns 0 if the signature generated successfully, 1 if an error occurred.
int uECC_sign(const uint8_t *p_privateKey, const uint8_t *msg,
              uint32_t msg_len, uint8_t *p_signature);

// Performs double sha256 hash on msg before signing.
// Returns 0 if the signature generated successfully, 1 if an error occurred.
int uECC_sign_double(const uint8_t *p_privateKey, const uint8_t *msg,
                     uint32_t msg_len, uint8_t *p_signature);

// Verify an ECDSA signature.
// Returns 0 if the signature is valid, 1 if it is invalid.
int uECC_verify_digest(const uint8_t p_publicKey[uECC_BYTES * 2],
                       const uint8_t p_hash[uECC_BYTES],
                       const uint8_t p_signature[uECC_BYTES * 2]);

// Performs sha256 hash on msg before verification
int uECC_verify(const uint8_t *p_publicKey, const uint8_t *p_signature,
                const uint8_t *msg, uint32_t msg_len);

// Performs double sha256 hash on msg before verification
int uECC_verify_double(const uint8_t *p_publicKey, const uint8_t *p_signature,
                       const uint8_t *msg, uint32_t msg_len);

// Get a child private key
// child = (master + z) % order
void uECC_generate_private_key(uint8_t *p_privateChild,
                               const uint8_t *p_privateMaster,
                               const uint8_t *z);

// Check if the private key is not equal to 0 and less than the order
// Returns 1 if valid
int uECC_isValid(uint8_t *p_key);

// Deterministic signatures following RFC6979
int uECC_generate_k_rfc6979_test(uint8_t *secret, const uint8_t *priv_key,
                                 const uint8_t *hash);

// Get the public key from the private key
void uECC_get_public_key65(const uint8_t p_privateKey[uECC_BYTES],
                           uint8_t p_publicKey[uECC_BYTES * 2 + 1]);
void uECC_get_public_key64(const uint8_t p_privateKey[uECC_BYTES],
                           uint8_t p_publicKey[uECC_BYTES * 2]);
void uECC_get_public_key33(const uint8_t p_privateKey[uECC_BYTES],
                           uint8_t p_publicKey[uECC_BYTES + 1]);


#endif /* _MICRO_ECC_H_ */
