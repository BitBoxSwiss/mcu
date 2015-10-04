/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */
/* Copyright 2015, Douglas J Bakkum - removed non secp256k1 curves; added supporting functions */


#include <string.h>

#include "uECC.h"
#include "sha2.h"
#include "hmac.h"
#include "random.h"


#ifndef uECC_PLATFORM
#if defined(__AVR__)
#define uECC_PLATFORM uECC_avr
#elif defined(__thumb2__) || defined(_M_ARMT) /* I think MSVC only supports Thumb-2 targets */
#define uECC_PLATFORM uECC_arm_thumb2
#elif defined(__thumb__)
#define uECC_PLATFORM uECC_arm_thumb
#elif defined(__arm__) || defined(_M_ARM)
#define uECC_PLATFORM uECC_arm
#elif defined(__i386__) || defined(_M_IX86) || defined(_X86_) || defined(__I86__)
#define uECC_PLATFORM uECC_x86
#elif defined(__amd64__) || defined(_M_X64)
#define uECC_PLATFORM uECC_x86_64
#else
#define uECC_PLATFORM uECC_arch_other
#endif
#endif

#if defined(__STDC_VERSION__)
#if __STDC_VERSION__ >= 199901L
#define RESTRICT restrict
#else
#define RESTRICT
#endif
#else
#define RESTRICT
#endif


#define MAX_TRIES 16


typedef uint32_t uECC_word_t;
typedef uint64_t uECC_dword_t;
typedef unsigned wordcount_t;
typedef int swordcount_t;
typedef int bitcount_t;
typedef int cmpresult_t;

#define HIGH_BIT_SET 0x80000000
#define uECC_WORD_BITS 32
#define uECC_WORD_BITS_SHIFT 5
#define uECC_WORD_BITS_MASK 0x01F

#define Curve_P {0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
#define Curve_B {0x00000007, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}
#define Curve_G { \
    {0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E}, \
    {0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77}}
#define Curve_N {0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}

#define uECC_WORDS 8
#define uECC_N_WORDS 8

typedef struct EccPoint {
    uECC_word_t x[uECC_WORDS];
    uECC_word_t y[uECC_WORDS];
} EccPoint;

static uECC_word_t curve_p[uECC_WORDS] = Curve_P;
static uECC_word_t curve_b[uECC_WORDS] = Curve_B;
static uECC_word_t curve_n[uECC_N_WORDS] = Curve_N;
static EccPoint curve_G = Curve_G;

static void vli_clear(uECC_word_t *p_vli);
static uECC_word_t vli_isZero(const uECC_word_t *p_vli);
static uECC_word_t vli_testBit(const uECC_word_t *p_vli, bitcount_t p_bit);
static bitcount_t vli_numBits(const uECC_word_t *p_vli, wordcount_t p_maxWords);
static void vli_set(uECC_word_t *p_dest, const uECC_word_t *p_src);
static cmpresult_t vli_cmp(uECC_word_t *p_left, uECC_word_t *p_right);
static void vli_rshift1(uECC_word_t *p_vli);
static uECC_word_t vli_add(uECC_word_t *p_result, uECC_word_t *p_left,
                           uECC_word_t *p_right);
static uECC_word_t vli_sub(uECC_word_t *p_result, uECC_word_t *p_left,
                           uECC_word_t *p_right);
static void vli_mult(uECC_word_t *p_result, uECC_word_t *p_left, uECC_word_t *p_right);
static void vli_modAdd(uECC_word_t *p_result, uECC_word_t *p_left, uECC_word_t *p_right,
                       uECC_word_t *p_mod);
static void vli_modSub(uECC_word_t *p_result, uECC_word_t *p_left, uECC_word_t *p_right,
                       uECC_word_t *p_mod);
static void vli_mmod_fast(uECC_word_t *RESTRICT p_result,
                          uECC_word_t *RESTRICT p_product);
static void vli_modMult_fast(uECC_word_t *p_result, uECC_word_t *p_left,
                             uECC_word_t *p_right);
static void vli_modInv(uECC_word_t *p_result, uECC_word_t *p_input, uECC_word_t *p_mod);
#if uECC_SQUARE_FUNC
static void vli_square(uECC_word_t *p_result, uECC_word_t *p_left);
static void vli_modSquare_fast(uECC_word_t *p_result, uECC_word_t *p_left);
#endif


#ifdef __GNUC__ /* Only support GCC inline asm for now */
#if (uECC_ASM && (uECC_PLATFORM == uECC_avr))
#include "asm_avr.inc"
#endif
#if (uECC_ASM && (uECC_PLATFORM == uECC_arm || uECC_PLATFORM == uECC_arm_thumb || uECC_PLATFORM == uECC_arm_thumb2))
#include "asm_arm.inc"
#endif
#endif


#if !defined(asm_clear)
static void vli_clear(uECC_word_t *p_vli)
{
    wordcount_t i;
    for (i = 0; i < uECC_WORDS; ++i) {
        p_vli[i] = 0;
    }
}
#endif

/* Returns 1 if p_vli == 0, 0 otherwise. */
#if !defined(asm_isZero)
static uECC_word_t vli_isZero(const uECC_word_t *p_vli)
{
    wordcount_t i;
    for (i = 0; i < uECC_WORDS; ++i) {
        if (p_vli[i]) {
            return 0;
        }
    }
    return 1;
}
#endif

/* Returns nonzero if bit p_bit of p_vli is set. */
#if !defined(asm_testBit)
static uECC_word_t vli_testBit(const uECC_word_t *p_vli, bitcount_t p_bit)
{
    return (p_vli[p_bit >> uECC_WORD_BITS_SHIFT] & ((uECC_word_t)1 <<
            (p_bit & uECC_WORD_BITS_MASK)));
}
#endif

/* Counts the number of words in p_vli. */
#if !defined(asm_numBits)
static wordcount_t vli_numDigits(const uECC_word_t *p_vli, wordcount_t p_maxWords)
{
    swordcount_t i;
    /* Search from the end until we find a non-zero digit.
       We do it in reverse because we expect that most digits will be nonzero. */
    for (i = p_maxWords - 1; i >= 0 && p_vli[i] == 0; --i) {
    }

    return (i + 1);
}

/* Counts the number of bits required to represent p_vli. */
static bitcount_t vli_numBits(const uECC_word_t *p_vli, wordcount_t p_maxWords)
{
    uECC_word_t i;
    uECC_word_t l_digit;

    wordcount_t l_numDigits = vli_numDigits(p_vli, p_maxWords);
    if (l_numDigits == 0) {
        return 0;
    }

    l_digit = p_vli[l_numDigits - 1];
    for (i = 0; l_digit; ++i) {
        l_digit >>= 1;
    }

    return (((bitcount_t)(l_numDigits - 1) << uECC_WORD_BITS_SHIFT) + i);
}
#endif /* !asm_numBits */

/* Sets p_dest = p_src. */
#if !defined(asm_set)
static void vli_set(uECC_word_t *p_dest, const uECC_word_t *p_src)
{
    wordcount_t i;
    for (i = 0; i < uECC_WORDS; ++i) {
        p_dest[i] = p_src[i];
    }
}
#endif

/* Returns sign of p_left - p_right. */
#if !defined(asm_cmp)
static cmpresult_t vli_cmp(uECC_word_t *p_left, uECC_word_t *p_right)
{
    swordcount_t i;
    for (i = uECC_WORDS - 1; i >= 0; --i) {
        if (p_left[i] > p_right[i]) {
            return 1;
        } else if (p_left[i] < p_right[i]) {
            return -1;
        }
    }
    return 0;
}
#endif

/* Computes p_vli = p_vli >> 1. */
#if !defined(asm_rshift1)
static void vli_rshift1(uECC_word_t *p_vli)
{
    uECC_word_t *l_end = p_vli;
    uECC_word_t l_carry = 0;

    p_vli += uECC_WORDS;
    while (p_vli-- > l_end) {
        uECC_word_t l_temp = *p_vli;
        *p_vli = (l_temp >> 1) | l_carry;
        l_carry = l_temp << (uECC_WORD_BITS - 1);
    }
}
#endif

/* Computes p_result = p_left + p_right, returning carry. Can modify in place. */
#if !defined(asm_add)
static uECC_word_t vli_add(uECC_word_t *p_result, uECC_word_t *p_left,
                           uECC_word_t *p_right)
{
    uECC_word_t l_carry = 0;
    wordcount_t i;
    for (i = 0; i < uECC_WORDS; ++i) {
        uECC_word_t l_sum = p_left[i] + p_right[i] + l_carry;
        if (l_sum != p_left[i]) {
            l_carry = (l_sum < p_left[i]);
        }
        p_result[i] = l_sum;
    }
    return l_carry;
}
#endif

/* Computes p_result = p_left - p_right, returning borrow. Can modify in place. */
#if !defined(asm_sub)
static uECC_word_t vli_sub(uECC_word_t *p_result, uECC_word_t *p_left,
                           uECC_word_t *p_right)
{
    uECC_word_t l_borrow = 0;
    wordcount_t i;
    for (i = 0; i < uECC_WORDS; ++i) {
        uECC_word_t l_diff = p_left[i] - p_right[i] - l_borrow;
        if (l_diff != p_left[i]) {
            l_borrow = (l_diff > p_left[i]);
        }
        p_result[i] = l_diff;
    }
    return l_borrow;
}
#endif

#if (!defined(asm_mult) || !defined(asm_square) || uECC_CURVE == uECC_secp256k1)
static void muladd(uECC_word_t a, uECC_word_t b, uECC_word_t *r0, uECC_word_t *r1,
                   uECC_word_t *r2)
{
    uECC_dword_t p = (uECC_dword_t)a * b;
    uECC_dword_t r01 = ((uECC_dword_t)(*r1) << uECC_WORD_BITS) | *r0;
    r01 += p;
    *r2 += (r01 < p);
    *r1 = r01 >> uECC_WORD_BITS;
    *r0 = (uECC_word_t)r01;
}
#define muladd_exists 1
#endif

#if !defined(asm_mult)
static void vli_mult(uECC_word_t *p_result, uECC_word_t *p_left, uECC_word_t *p_right)
{
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;

    wordcount_t i, k;

    /* Compute each digit of p_result in sequence, maintaining the carries. */
    for (k = 0; k < uECC_WORDS; ++k) {
        for (i = 0; i <= k; ++i) {
            muladd(p_left[i], p_right[k - i], &r0, &r1, &r2);
        }
        p_result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    for (k = uECC_WORDS; k < uECC_WORDS * 2 - 1; ++k) {
        for (i = (k + 1) - uECC_WORDS; i < uECC_WORDS; ++i) {
            muladd(p_left[i], p_right[k - i], &r0, &r1, &r2);
        }
        p_result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }

    p_result[uECC_WORDS * 2 - 1] = r0;
}
#endif

#if uECC_SQUARE_FUNC

#if !defined(asm_square)
static void mul2add(uECC_word_t a, uECC_word_t b, uECC_word_t *r0, uECC_word_t *r1,
                    uECC_word_t *r2)
{
    uECC_dword_t p = (uECC_dword_t)a * b;
    uECC_dword_t r01 = ((uECC_dword_t)(*r1) << uECC_WORD_BITS) | *r0;
    *r2 += (p >> (uECC_WORD_BITS * 2 - 1));
    p *= 2;
    r01 += p;
    *r2 += (r01 < p);
    *r1 = r01 >> uECC_WORD_BITS;
    *r0 = (uECC_word_t)r01;
}

static void vli_square(uECC_word_t *p_result, uECC_word_t *p_left)
{
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;

    wordcount_t i, k;

    for (k = 0; k < uECC_WORDS * 2 - 1; ++k) {
        uECC_word_t l_min = (k < uECC_WORDS ? 0 : (k + 1) - uECC_WORDS);
        for (i = l_min; i <= k && i <= k - i; ++i) {
            if (i < k - i) {
                mul2add(p_left[i], p_left[k - i], &r0, &r1, &r2);
            } else {
                muladd(p_left[i], p_left[k - i], &r0, &r1, &r2);
            }
        }
        p_result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }

    p_result[uECC_WORDS * 2 - 1] = r0;
}
#endif

#else /* uECC_SQUARE_FUNC */

#define vli_square(result, left, size) vli_mult((result), (left), (left), (size))

#endif /* uECC_SQUARE_FUNC */


/* Computes p_result = (p_left + p_right) % p_mod.
   Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod. */
#if !defined(asm_modAdd)
static void vli_modAdd(uECC_word_t *p_result, uECC_word_t *p_left, uECC_word_t *p_right,
                       uECC_word_t *p_mod)
{
    uECC_word_t l_carry = vli_add(p_result, p_left, p_right);
    if (l_carry || vli_cmp(p_result, p_mod) >= 0) {
        /* p_result > p_mod (p_result = p_mod + remainder), so subtract p_mod to get remainder. */
        vli_sub(p_result, p_result, p_mod);
    }
}
#endif

/* Computes p_result = (p_left - p_right) % p_mod.
   Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod. */
#if !defined(asm_modSub)
static void vli_modSub(uECC_word_t *p_result, uECC_word_t *p_left, uECC_word_t *p_right,
                       uECC_word_t *p_mod)
{
    uECC_word_t l_borrow = vli_sub(p_result, p_left, p_right);
    if (l_borrow) {
        /* In this case, p_result == -diff == (max int) - diff.
           Since -x % d == d - x, we can get the correct result from p_result + p_mod (with overflow). */
        vli_add(p_result, p_result, p_mod);
    }
}
#endif

#if !defined(asm_modSub_fast)
#define vli_modSub_fast(result, left, right) vli_modSub((result), (left), (right), curve_p)
#endif

#if !defined(asm_mmod_fast)

/* omega_mult() is defined farther below for the different curves / word sizes */
static void omega_mult(uECC_word_t *RESTRICT p_result, uECC_word_t *RESTRICT p_right);

/* Computes p_result = p_product % curve_p
    see http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf page 354

    Note that this only works if log2(omega) < log2(p)/2 */
static void vli_mmod_fast(uECC_word_t *RESTRICT p_result, uECC_word_t *RESTRICT p_product)
{
    uECC_word_t l_tmp[2 * uECC_WORDS];
    uECC_word_t l_carry;

    vli_clear(l_tmp);
    vli_clear(l_tmp + uECC_WORDS);

    omega_mult(l_tmp, p_product + uECC_WORDS); /* (Rq, q) = q * c */

    l_carry = vli_add(p_result, p_product, l_tmp); /* (C, r) = r + q       */
    vli_clear(p_product);
    omega_mult(p_product, l_tmp + uECC_WORDS); /* Rq*c */
    l_carry += vli_add(p_result, p_result, p_product); /* (C1, r) = r + Rq*c */

    while (l_carry > 0) {
        --l_carry;
        vli_sub(p_result, p_result, curve_p);
    }

    if (vli_cmp(p_result, curve_p) > 0) {
        vli_sub(p_result, p_result, curve_p);
    }
}


static void omega_mult(uint32_t *RESTRICT p_result, uint32_t *RESTRICT p_right)
{
    /* Multiply by (2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1). */
    uint32_t l_carry = 0;
    wordcount_t k;

    for (k = 0; k < uECC_WORDS; ++k) {
        uint64_t p = (uint64_t)0x3D1 * p_right[k] + l_carry;
        p_result[k] = (p & 0xffffffff);
        l_carry = p >> 32;
    }
    p_result[uECC_WORDS] = l_carry;

    p_result[1 + uECC_WORDS] = vli_add(p_result + 1, p_result + 1,
                                       p_right); /* add the 2^32 multiple */
}


#endif /* !asm_mmod_fast */

/* Computes p_result = (p_left * p_right) % curve_p. */
static void vli_modMult_fast(uECC_word_t *p_result, uECC_word_t *p_left,
                             uECC_word_t *p_right)
{
    uECC_word_t l_product[2 * uECC_WORDS];
    vli_mult(l_product, p_left, p_right);
    vli_mmod_fast(p_result, l_product);
}

#if uECC_SQUARE_FUNC

/* Computes p_result = p_left^2 % curve_p. */
static void vli_modSquare_fast(uECC_word_t *p_result, uECC_word_t *p_left)
{
    uECC_word_t l_product[2 * uECC_WORDS];
    vli_square(l_product, p_left);
    vli_mmod_fast(p_result, l_product);
}

#else /* uECC_SQUARE_FUNC */

#define vli_modSquare_fast(result, left) vli_modMult_fast((result), (left), (left))

#endif /* uECC_SQUARE_FUNC */


#define EVEN(vli) (!(vli[0] & 1))
/* Computes p_result = (1 / p_input) % p_mod. All VLIs are the same size.
   See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
   https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf */
#if !defined(asm_modInv)
static void vli_modInv(uECC_word_t *p_result, uECC_word_t *p_input, uECC_word_t *p_mod)
{
    uECC_word_t a[uECC_WORDS], b[uECC_WORDS], u[uECC_WORDS], v[uECC_WORDS];
    uECC_word_t l_carry;
    cmpresult_t l_cmpResult;

    if (vli_isZero(p_input)) {
        vli_clear(p_result);
        return;
    }

    vli_set(a, p_input);
    vli_set(b, p_mod);
    vli_clear(u);
    u[0] = 1;
    vli_clear(v);
    while ((l_cmpResult = vli_cmp(a, b)) != 0) {
        l_carry = 0;
        if (EVEN(a)) {
            vli_rshift1(a);
            if (!EVEN(u)) {
                l_carry = vli_add(u, u, p_mod);
            }
            vli_rshift1(u);
            if (l_carry) {
                u[uECC_WORDS - 1] |= HIGH_BIT_SET;
            }
        } else if (EVEN(b)) {
            vli_rshift1(b);
            if (!EVEN(v)) {
                l_carry = vli_add(v, v, p_mod);
            }
            vli_rshift1(v);
            if (l_carry) {
                v[uECC_WORDS - 1] |= HIGH_BIT_SET;
            }
        } else if (l_cmpResult > 0) {
            vli_sub(a, a, b);
            vli_rshift1(a);
            if (vli_cmp(u, v) < 0) {
                vli_add(u, u, p_mod);
            }
            vli_sub(u, u, v);
            if (!EVEN(u)) {
                l_carry = vli_add(u, u, p_mod);
            }
            vli_rshift1(u);
            if (l_carry) {
                u[uECC_WORDS - 1] |= HIGH_BIT_SET;
            }
        } else {
            vli_sub(b, b, a);
            vli_rshift1(b);
            if (vli_cmp(v, u) < 0) {
                vli_add(v, v, p_mod);
            }
            vli_sub(v, v, u);
            if (!EVEN(v)) {
                l_carry = vli_add(v, v, p_mod);
            }
            vli_rshift1(v);
            if (l_carry) {
                v[uECC_WORDS - 1] |= HIGH_BIT_SET;
            }
        }
    }

    vli_set(p_result, u);
}
#endif /* !asm_modInv */

/* ------ Point operations ------ */

/* Returns 1 if p_point is the point at infinity, 0 otherwise. */
static cmpresult_t EccPoint_isZero(EccPoint *p_point)
{
    return (vli_isZero(p_point->x) && vli_isZero(p_point->y));
}

/* Point multiplication algorithm using Montgomery's ladder with co-Z coordinates.
From http://eprint.iacr.org/2011/338.pdf
*/

/* Double in place */
static void EccPoint_double_jacobian(uECC_word_t *RESTRICT X1, uECC_word_t *RESTRICT Y1,
                                     uECC_word_t *RESTRICT Z1)
{
    /* t1 = X, t2 = Y, t3 = Z */
    uECC_word_t t4[uECC_WORDS];
    uECC_word_t t5[uECC_WORDS];

    if (vli_isZero(Z1)) {
        return;
    }

    vli_modSquare_fast(t5, Y1);   /* t5 = y1^2 */
    vli_modMult_fast(t4, X1, t5); /* t4 = x1*y1^2 = A */
    vli_modSquare_fast(X1, X1);   /* t1 = x1^2 */
    vli_modSquare_fast(t5, t5);   /* t5 = y1^4 */
    vli_modMult_fast(Z1, Y1, Z1); /* t3 = y1*z1 = z3 */

    vli_modAdd(Y1, X1, X1, curve_p); /* t2 = 2*x1^2 */
    vli_modAdd(Y1, Y1, X1, curve_p); /* t2 = 3*x1^2 */
    if (vli_testBit(Y1, 0)) {
        uECC_word_t l_carry = vli_add(Y1, Y1, curve_p);
        vli_rshift1(Y1);
        Y1[uECC_WORDS - 1] |= l_carry << (uECC_WORD_BITS - 1);
    } else {
        vli_rshift1(Y1);
    }
    /* t2 = 3/2*(x1^2) = B */

    vli_modSquare_fast(X1, Y1);   /* t1 = B^2 */
    vli_modSub(X1, X1, t4, curve_p); /* t1 = B^2 - A */
    vli_modSub(X1, X1, t4, curve_p); /* t1 = B^2 - 2A = x3 */

    vli_modSub(t4, t4, X1, curve_p); /* t4 = A - x3 */
    vli_modMult_fast(Y1, Y1, t4);    /* t2 = B * (A - x3) */
    vli_modSub(Y1, Y1, t5, curve_p); /* t2 = B * (A - x3) - y1^4 = y3 */
}

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
static void apply_z(uECC_word_t *RESTRICT X1, uECC_word_t *RESTRICT Y1,
                    uECC_word_t *RESTRICT Z)
{
    uECC_word_t t1[uECC_WORDS];

    vli_modSquare_fast(t1, Z);    /* z^2 */
    vli_modMult_fast(X1, X1, t1); /* x1 * z^2 */
    vli_modMult_fast(t1, t1, Z);  /* z^3 */
    vli_modMult_fast(Y1, Y1, t1); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
static void XYcZ_initial_double(uECC_word_t *RESTRICT X1, uECC_word_t *RESTRICT Y1,
                                uECC_word_t *RESTRICT X2, uECC_word_t *RESTRICT Y2,
                                const uECC_word_t *RESTRICT p_initialZ)
{
    uECC_word_t z[uECC_WORDS];

    vli_set(X2, X1);
    vli_set(Y2, Y1);

    vli_clear(z);
    z[0] = 1;
    if (p_initialZ) {
        vli_set(z, p_initialZ);
    }

    apply_z(X1, Y1, z);

    EccPoint_double_jacobian(X1, Y1, z);

    apply_z(X2, Y2, z);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
   or P => P', Q => P + Q
*/
static void XYcZ_add(uECC_word_t *RESTRICT X1, uECC_word_t *RESTRICT Y1,
                     uECC_word_t *RESTRICT X2, uECC_word_t *RESTRICT Y2)
{
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uECC_word_t t5[uECC_WORDS];

    vli_modSub_fast(t5, X2, X1); /* t5 = x2 - x1 */
    vli_modSquare_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
    vli_modMult_fast(X1, X1, t5);    /* t1 = x1*A = B */
    vli_modMult_fast(X2, X2, t5);    /* t3 = x2*A = C */
    vli_modSub_fast(Y2, Y2, Y1); /* t4 = y2 - y1 */
    vli_modSquare_fast(t5, Y2);      /* t5 = (y2 - y1)^2 = D */

    vli_modSub_fast(t5, t5, X1); /* t5 = D - B */
    vli_modSub_fast(t5, t5, X2); /* t5 = D - B - C = x3 */
    vli_modSub_fast(X2, X2, X1); /* t3 = C - B */
    vli_modMult_fast(Y1, Y1, X2);    /* t2 = y1*(C - B) */
    vli_modSub_fast(X2, X1, t5); /* t3 = B - x3 */
    vli_modMult_fast(Y2, Y2, X2);    /* t4 = (y2 - y1)*(B - x3) */
    vli_modSub_fast(Y2, Y2, Y1); /* t4 = y3 */

    vli_set(X2, t5);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
   or P => P - Q, Q => P + Q
*/
static void XYcZ_addC(uECC_word_t *RESTRICT X1, uECC_word_t *RESTRICT Y1,
                      uECC_word_t *RESTRICT X2, uECC_word_t *RESTRICT Y2)
{
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uECC_word_t t5[uECC_WORDS];
    uECC_word_t t6[uECC_WORDS];
    uECC_word_t t7[uECC_WORDS];

    vli_modSub_fast(t5, X2, X1); /* t5 = x2 - x1 */
    vli_modSquare_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
    vli_modMult_fast(X1, X1, t5);    /* t1 = x1*A = B */
    vli_modMult_fast(X2, X2, t5);    /* t3 = x2*A = C */
    vli_modAdd(t5, Y2, Y1, curve_p); /* t4 = y2 + y1 */
    vli_modSub_fast(Y2, Y2, Y1); /* t4 = y2 - y1 */

    vli_modSub_fast(t6, X2, X1); /* t6 = C - B */
    vli_modMult_fast(Y1, Y1, t6);    /* t2 = y1 * (C - B) */
    vli_modAdd(t6, X1, X2, curve_p); /* t6 = B + C */
    vli_modSquare_fast(X2, Y2);      /* t3 = (y2 - y1)^2 */
    vli_modSub_fast(X2, X2, t6); /* t3 = x3 */

    vli_modSub_fast(t7, X1, X2); /* t7 = B - x3 */
    vli_modMult_fast(Y2, Y2, t7);    /* t4 = (y2 - y1)*(B - x3) */
    vli_modSub_fast(Y2, Y2, Y1); /* t4 = y3 */

    vli_modSquare_fast(t7, t5);      /* t7 = (y2 + y1)^2 = F */
    vli_modSub_fast(t7, t7, t6); /* t7 = x3' */
    vli_modSub_fast(t6, t7, X1); /* t6 = x3' - B */
    vli_modMult_fast(t6, t6, t5);    /* t6 = (y2 + y1)*(x3' - B) */
    vli_modSub_fast(Y1, t6, Y1); /* t2 = y3' */

    vli_set(X1, t7);
}

static void EccPoint_mult(EccPoint *RESTRICT p_result, EccPoint *RESTRICT p_point,
                          const uECC_word_t *RESTRICT p_scalar, const uECC_word_t *RESTRICT p_initialZ,
                          bitcount_t p_numBits)
{
    /* R0 and R1 */
    uECC_word_t Rx[2][uECC_WORDS];
    uECC_word_t Ry[2][uECC_WORDS];
    uECC_word_t z[uECC_WORDS];

    bitcount_t i;
    uECC_word_t nb;

    vli_set(Rx[1], p_point->x);
    vli_set(Ry[1], p_point->y);

    XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], p_initialZ);

    for (i = p_numBits - 2; i > 0; --i) {
        nb = !vli_testBit(p_scalar, i);
        XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
        XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
    }

    nb = !vli_testBit(p_scalar, 0);
    XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);

    /* Find final 1/Z value. */
    vli_modSub_fast(z, Rx[1], Rx[0]); /* X1 - X0 */
    vli_modMult_fast(z, z, Ry[1 - nb]);   /* Yb * (X1 - X0) */
    vli_modMult_fast(z, z, p_point->x);   /* xP * Yb * (X1 - X0) */
    vli_modInv(z, z, curve_p);            /* 1 / (xP * Yb * (X1 - X0)) */
    vli_modMult_fast(z, z, p_point->y);   /* yP / (xP * Yb * (X1 - X0)) */
    vli_modMult_fast(z, z, Rx[1 - nb]);   /* Xb * yP / (xP * Yb * (X1 - X0)) */
    /* End 1/Z calculation */

    XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);

    apply_z(Rx[0], Ry[0], z);

    vli_set(p_result->x, Rx[0]);
    vli_set(p_result->y, Ry[0]);
}

/* Compute a = sqrt(a) (mod curve_p). */
static void mod_sqrt(uECC_word_t *a)
{
    bitcount_t i;
    uECC_word_t p1[uECC_WORDS] = {1};
    uECC_word_t l_result[uECC_WORDS] = {1};

    /* Since curve_p == 3 (mod 4) for all supported curves, we can
       compute sqrt(a) = a^((curve_p + 1) / 4) (mod curve_p). */
    vli_add(p1, curve_p, p1); /* p1 = curve_p + 1 */
    for (i = vli_numBits(p1, uECC_WORDS) - 1; i > 1; --i) {
        vli_modSquare_fast(l_result, l_result);
        if (vli_testBit(p1, i)) {
            vli_modMult_fast(l_result, l_result, a);
        }
    }
    vli_set(a, l_result);
}

static void vli_nativeToBytes(uint8_t *p_bytes, const uint32_t *p_native)
{
    unsigned i;
    for (i = 0; i < uECC_WORDS; ++i) {
        uint8_t *p_digit = p_bytes + 4 * (uECC_WORDS - 1 - i);
        p_digit[0] = p_native[i] >> 24;
        p_digit[1] = p_native[i] >> 16;
        p_digit[2] = p_native[i] >> 8;
        p_digit[3] = p_native[i];
    }
}

static void vli_bytesToNative(uint32_t *p_native, const uint8_t *p_bytes)
{
    unsigned i;
    for (i = 0; i < uECC_WORDS; ++i) {
        const uint8_t *p_digit = p_bytes + 4 * (uECC_WORDS - 1 - i);
        p_native[i] = ((uint32_t)p_digit[0] << 24) | ((uint32_t)p_digit[1] << 16) | ((
                          uint32_t)p_digit[2] << 8) | (uint32_t)p_digit[3];
    }
}

static void uECC_compress(const uint8_t p_publicKey[uECC_BYTES * 2],
                          uint8_t p_compressed[uECC_BYTES + 1])
{
    wordcount_t i;
    for (i = 0; i < uECC_BYTES; ++i) {
        p_compressed[i + 1] = p_publicKey[i];
    }
    p_compressed[0] = 2 + (p_publicKey[uECC_BYTES * 2 - 1] & 0x01);
}

void uECC_decompress(const uint8_t p_compressed[uECC_BYTES + 1],
                     uint8_t p_publicKey[uECC_BYTES * 2])
{
    EccPoint l_point;
    vli_bytesToNative(l_point.x, p_compressed + 1);

    vli_modSquare_fast(l_point.y, l_point.x); /* r = x^2 */
    vli_modMult_fast(l_point.y, l_point.y, l_point.x); /* r = x^3 */
    vli_modAdd(l_point.y, l_point.y, curve_b, curve_p); /* r = x^3 + b */

    mod_sqrt(l_point.y);

    if ((l_point.y[0] & 0x01) != (p_compressed[0] & 0x01)) {
        vli_sub(l_point.y, curve_p, l_point.y);
    }

    vli_nativeToBytes(p_publicKey, l_point.x);
    vli_nativeToBytes(p_publicKey + uECC_BYTES, l_point.y);
}

/* -------- ECDSA code -------- */

#define vli_modInv_n vli_modInv
#define vli_modAdd_n vli_modAdd

static void vli2_rshift1(uECC_word_t *p_vli)
{
    vli_rshift1(p_vli);
    p_vli[uECC_WORDS - 1] |= p_vli[uECC_WORDS] << (uECC_WORD_BITS - 1);
    vli_rshift1(p_vli + uECC_WORDS);
}

static uECC_word_t vli2_sub(uECC_word_t *p_result, uECC_word_t *p_left,
                            uECC_word_t *p_right)
{
    uECC_word_t l_borrow = 0;
    wordcount_t i;
    for (i = 0; i < uECC_WORDS * 2; ++i) {
        uECC_word_t l_diff = p_left[i] - p_right[i] - l_borrow;
        if (l_diff != p_left[i]) {
            l_borrow = (l_diff > p_left[i]);
        }
        p_result[i] = l_diff;
    }
    return l_borrow;
}

/* Computes p_result = (p_left * p_right) % curve_n. */
static void vli_modMult_n(uECC_word_t *p_result, uECC_word_t *p_left,
                          uECC_word_t *p_right)
{
    uECC_word_t l_product[2 * uECC_WORDS];
    uECC_word_t l_modMultiple[2 * uECC_WORDS];
    uECC_word_t l_tmp[2 * uECC_WORDS];
    uECC_word_t *v[2] = {l_tmp, l_product};

    vli_mult(l_product, p_left, p_right);
    vli_set(l_modMultiple + uECC_WORDS,
            curve_n); /* works if curve_n has its highest bit set */
    vli_clear(l_modMultiple);

    bitcount_t i;
    uECC_word_t l_index = 1;
    for (i = 0; i <= uECC_BYTES * 8; ++i) {
        uECC_word_t l_borrow = vli2_sub(v[1 - l_index], v[l_index], l_modMultiple);
        l_index = !(l_index ^ l_borrow); /* Swap the index if there was no borrow */
        vli2_rshift1(l_modMultiple);
    }

    vli_set(p_result, v[l_index]);
}

static bitcount_t smax(bitcount_t a, bitcount_t b)
{
    return (a > b ? a : b);
}


/* Compute a shared secret given your secret key and someone's public key.
   Returns 0 on success. */
int uECC_shared_secret(const uint8_t public_key[uECC_BYTES * 2],
                       const uint8_t private_key[uECC_BYTES],
                       uint8_t secret[uECC_BYTES])
{
    EccPoint public;
    EccPoint product;
    uECC_word_t private[uECC_WORDS];
    uECC_word_t tmp[uECC_WORDS];
    uECC_word_t *p2[2] = {private, tmp};
    uECC_word_t random[uECC_WORDS];
    uECC_word_t *initial_Z = 0;
    uECC_word_t tries;
    uECC_word_t carry;
    uint8_t secret_point[uECC_BYTES * 2];
    uint8_t secret_compressed[uECC_BYTES + 1];

    // Try to get a random initial Z value to improve protection against side-channel
    // attacks. If the RNG fails every time (eg it was not defined), we continue so that
    // uECC_shared_secret() can still work without an RNG defined.
    for (tries = 0; tries < MAX_TRIES; ++tries) {
        random_bytes((uint8_t *)random, sizeof(random), 0);
        if ((uint8_t *)random  && !vli_isZero(random)) {
            initial_Z = random;
            break;
        }
    }

    vli_bytesToNative(private, private_key);
    vli_bytesToNative(public.x, public_key);
    vli_bytesToNative(public.y, public_key + uECC_BYTES);

    // Regularize the bitcount for the private key so that attackers cannot use a side channel
    // attack to learn the number of leading zeros.
    carry = vli_add(private, private, curve_n);
    vli_add(tmp, private, curve_n);
    EccPoint_mult(&product, &public, p2[!carry], initial_Z, (uECC_BYTES * 8) + 1);

    // Return the hash of the compressed point as the shared secret
    vli_nativeToBytes(secret_point, product.x);
    vli_nativeToBytes(secret_point + uECC_BYTES, product.y);
    uECC_compress(secret_point, secret_compressed);

    sha256_Raw(secret_compressed, uECC_BYTES + 1, secret);

    return EccPoint_isZero(&product);
}




/* Performs sha256 hash on msg before signing.
   Returns 0 on success. */
int uECC_sign(const uint8_t *p_privateKey, const uint8_t *msg, uint32_t msg_len,
              uint8_t *p_signature)
{
    uint8_t p_hash[uECC_BYTES];
    if (uECC_BYTES != SHA256_DIGEST_LENGTH) {
        return 1;
    }
    sha256_Raw(msg, msg_len, p_hash);
    return uECC_sign_digest(p_privateKey, p_hash, p_signature);
}

/* Performs a double sha256 hash on msg before signing.
   Returns 0 on success. */
int uECC_sign_double(const uint8_t *p_privateKey, const uint8_t *msg, uint32_t msg_len,
                     uint8_t *p_signature)
{
    uint8_t p_hash[uECC_BYTES];
    if (uECC_BYTES != SHA256_DIGEST_LENGTH) {
        return 1;
    }
    sha256_Raw(msg, msg_len, p_hash);
    sha256_Raw(p_hash, uECC_BYTES, p_hash);
    return uECC_sign_digest(p_privateKey, p_hash, p_signature);
}

/* ECDSA signature.
   Returns 0 always. */
int uECC_sign_digest(const uint8_t p_privateKey[uECC_BYTES],
                     const uint8_t p_hash[uECC_BYTES], uint8_t p_signature[uECC_BYTES * 2])
{
    uECC_word_t k[uECC_N_WORDS];
    uECC_word_t l_tmp[uECC_N_WORDS];
    uECC_word_t s[uECC_N_WORDS];
    uECC_word_t *k2[2] = {l_tmp, s};
    EccPoint p;
    uint8_t k_b[32];

    do {
    repeat:
        // Deterministic K
        uECC_generate_k_rfc6979_test(k_b, p_privateKey, p_hash);
        vli_bytesToNative(k, k_b);

        if (vli_isZero(k)) {
            goto repeat;
        }

        if (vli_cmp(curve_n, k) != 1) {
            goto repeat;
        }

        /* make sure that we don't leak timing information about k. See http://eprint.iacr.org/2011/232.pdf */
        uECC_word_t l_carry = vli_add(l_tmp, k, curve_n);
        vli_add(s, l_tmp, curve_n);

        /* p = k * G */
        EccPoint_mult(&p, &curve_G, k2[!l_carry], 0, (uECC_BYTES * 8) + 1);

        /* r = x1 (mod n) */
        if (vli_cmp(curve_n, p.x) != 1) {
            vli_sub(p.x, p.x, curve_n);
        }
    } while (vli_isZero(p.x));


    /* Prevent side channel analysis of vli_modInv() to determine
       bits of k / the private key by premultiplying by a random number */
    random_init();
    random_bytes((uint8_t *)l_tmp, sizeof(l_tmp) / 2, 0); // call random once to improve speed
    // multiplies by a 16 instead of 32 byte number
    vli_modMult_n(k, k, l_tmp); /* k' = rand * k */
    vli_modInv_n(k, k, curve_n); /* k = 1 / k' */
    vli_modMult_n(k, k, l_tmp); /* k = 1 / k */

    vli_nativeToBytes(p_signature, p.x); /* store r */

    l_tmp[uECC_N_WORDS - 1] = 0;
    vli_bytesToNative(l_tmp, p_privateKey); /* tmp = d */
    s[uECC_N_WORDS - 1] = 0;
    vli_set(s, p.x);
    vli_modMult_n(s, l_tmp, s); /* s = r*d */

    vli_bytesToNative(l_tmp, p_hash);
    vli_modAdd_n(s, l_tmp, s, curve_n); /* s = e + r*d */
    vli_modMult_n(s, s, k); /* s = (e + r*d) / k */
    vli_nativeToBytes(p_signature + uECC_BYTES, s);

    return 0;
}

/* Returns the decompressed public key in p_publicKey */
static int uECC_read_pubkey(const uint8_t *publicKey, uint8_t *p_publicKey)
{
    if (publicKey[0] == 0x04) {
        memcpy(p_publicKey, publicKey + 1, uECC_BYTES * 2);
        return 1;
    }
    if (publicKey[0] == 0x02 || publicKey[0] == 0x03) { // compute missing y coords
        uECC_decompress(publicKey, p_publicKey);
        return 1;
    }
    // error
    return 0;
}

/* Performs sha256 hash on msg before verification */
int uECC_verify(const uint8_t *publicKey, const uint8_t *p_signature,
                const uint8_t *msg, uint32_t msg_len)
{
    uint8_t p_hash[uECC_BYTES];
    if (uECC_BYTES != SHA256_DIGEST_LENGTH) {
        return 1;
    }
    sha256_Raw(msg, msg_len, p_hash);
    return uECC_verify_digest(publicKey, p_hash, p_signature);
}

/* Performs a double sha256 hash on msg before verification */
int uECC_verify_double(const uint8_t *publicKey, const uint8_t *p_signature,
                       const uint8_t *msg, uint32_t msg_len)
{
    uint8_t p_hash[uECC_BYTES];
    if (uECC_BYTES != SHA256_DIGEST_LENGTH) {
        return 1;
    }
    sha256_Raw(msg, msg_len, p_hash);
    sha256_Raw(p_hash, uECC_BYTES, p_hash);
    return uECC_verify_digest(publicKey, p_hash, p_signature);
}

/* Verify an ECDSA signature.
   Returns 1 if the signature is valid, 0 if it is invalid. */
int uECC_verify_digest(const uint8_t *publicKey,
                       const uint8_t p_hash[uECC_BYTES],
                       const uint8_t p_signature[uECC_BYTES * 2])
{
    uint8_t p_publicKey[uECC_BYTES * 2];

    if (!uECC_read_pubkey(publicKey, p_publicKey)) {
        return 1;
    }

    uECC_word_t u1[uECC_N_WORDS], u2[uECC_N_WORDS];
    uECC_word_t z[uECC_N_WORDS];
    EccPoint l_public, l_sum;
    uECC_word_t rx[uECC_WORDS];
    uECC_word_t ry[uECC_WORDS];
    uECC_word_t tx[uECC_WORDS];
    uECC_word_t ty[uECC_WORDS];
    uECC_word_t tz[uECC_WORDS];

    uECC_word_t r[uECC_N_WORDS], s[uECC_N_WORDS];
    r[uECC_N_WORDS - 1] = 0;
    s[uECC_N_WORDS - 1] = 0;

    vli_bytesToNative(l_public.x, p_publicKey);
    vli_bytesToNative(l_public.y, p_publicKey + uECC_BYTES);
    vli_bytesToNative(r, p_signature);
    vli_bytesToNative(s, p_signature + uECC_BYTES);

    if (vli_isZero(r) || vli_isZero(s)) {
        /* r, s must not be 0. */
        return 1;
    }

    /* Calculate u1 and u2. */
    vli_modInv_n(z, s, curve_n); /* Z = s^-1 */
    u1[uECC_N_WORDS - 1] = 0;
    vli_bytesToNative(u1, p_hash);
    vli_modMult_n(u1, u1, z); /* u1 = e/s */
    vli_modMult_n(u2, r, z); /* u2 = r/s */

    /* Calculate l_sum = G + Q. */
    vli_set(l_sum.x, l_public.x);
    vli_set(l_sum.y, l_public.y);
    vli_set(tx, curve_G.x);
    vli_set(ty, curve_G.y);
    vli_modSub_fast(z, l_sum.x, tx); /* Z = x2 - x1 */
    XYcZ_add(tx, ty, l_sum.x, l_sum.y);
    vli_modInv(z, z, curve_p); /* Z = 1/Z */
    apply_z(l_sum.x, l_sum.y, z);

    /* Use Shamir's trick to calculate u1*G + u2*Q */
    EccPoint *l_points[4] = {0, &curve_G, &l_public, &l_sum};
    bitcount_t l_numBits = smax(vli_numBits(u1, uECC_N_WORDS), vli_numBits(u2, uECC_N_WORDS));

    EccPoint *l_point = l_points[(!!vli_testBit(u1, l_numBits - 1)) | ((!!vli_testBit(u2,
                                 l_numBits - 1)) << 1)];
    vli_set(rx, l_point->x);
    vli_set(ry, l_point->y);
    vli_clear(z);
    z[0] = 1;

    bitcount_t i;
    for (i = l_numBits - 2; i >= 0; --i) {
        EccPoint_double_jacobian(rx, ry, z);

        uECC_word_t l_index = (!!vli_testBit(u1, i)) | ((!!vli_testBit(u2, i)) << 1);
        l_point = l_points[l_index];
        if (l_point) {
            vli_set(tx, l_point->x);
            vli_set(ty, l_point->y);
            apply_z(tx, ty, z);
            vli_modSub_fast(tz, rx, tx); /* Z = x2 - x1 */
            XYcZ_add(tx, ty, rx, ry);
            vli_modMult_fast(z, z, tz);
        }
    }

    vli_modInv(z, z, curve_p); /* Z = 1/Z */
    apply_z(rx, ry, z);

    /* v = x1 (mod n) */
    if (vli_cmp(curve_n, rx) != 1) {
        vli_sub(rx, rx, curve_n);
    }

    /* Accept only if v == r. */
    return !(vli_cmp(rx, r) == 0); // 0 on success
}

/* Get a child private key
   child = (master + z) % order */
void uECC_generate_private_key(uint8_t *p_privateChild, const uint8_t *p_privateMaster,
                               const uint8_t *z)
{
    uECC_word_t l_privateChild[uECC_WORDS];
    uECC_word_t l_privateMaster[uECC_WORDS];
    uECC_word_t l_z[uECC_WORDS];

    vli_bytesToNative(l_privateMaster, p_privateMaster);
    vli_bytesToNative(l_z, z);

    vli_modAdd(l_privateChild, l_privateMaster, l_z, curve_n);

    vli_nativeToBytes(p_privateChild, l_privateChild);
}

/* Check if the private key is not equal to 0 and less than the order
   Returns 1 if valid */
int uECC_isValid(uint8_t *p_key)
{
    uECC_word_t l_key[uECC_WORDS];
    vli_bytesToNative(l_key, p_key);

    return (!vli_isZero(l_key) && vli_cmp(curve_n, l_key) == 1);
}

/* Get the public key from the private key */
void uECC_get_public_key33(const uint8_t p_privateKey[uECC_BYTES],
                           uint8_t p_publicKey[uECC_BYTES + 1])
{
    uint8_t p_publicKey_long[uECC_BYTES * 2];
    uECC_get_public_key64(p_privateKey, p_publicKey_long);
    uECC_compress(p_publicKey_long, p_publicKey);
}

/* Get the public key from the private key */
void uECC_get_public_key65(const uint8_t p_privateKey[uECC_BYTES],
                           uint8_t p_publicKey[uECC_BYTES * 2 + 1])
{
    uint8_t *p = p_publicKey;
    p[0] = 0x04;
    uECC_get_public_key64(p_privateKey, p + 1);
}

/* Get the public key from the private key */
void uECC_get_public_key64(const uint8_t p_privateKey[uECC_BYTES],
                           uint8_t p_publicKey[uECC_BYTES * 2])
{
    EccPoint l_public;
    uECC_word_t l_private[uECC_WORDS];

    vli_bytesToNative(l_private, p_privateKey);

    EccPoint_mult(&l_public, &curve_G, l_private, 0, vli_numBits(l_private, uECC_WORDS));

    vli_nativeToBytes(p_publicKey, l_public.x);
    vli_nativeToBytes(p_publicKey + uECC_BYTES, l_public.y);
}

/* generate K in a deterministic way, according to RFC6979
   http://tools.ietf.org/html/rfc6979 */
int uECC_generate_k_rfc6979_test(uint8_t *secret, const uint8_t *priv_key,
                                 const uint8_t *hash)
{
    int i;
    uint8_t v[32], k[32], bx[2 * 32], buf[32 + 1 + sizeof(bx)], z1[32];
    uECC_word_t l_z1[uECC_WORDS];
    uECC_word_t l_secret[uECC_WORDS];

    vli_bytesToNative(l_z1, hash);
    while ( vli_cmp(curve_p, l_z1) != 1) {
        vli_sub(l_z1, l_z1, curve_p);
    }
    vli_nativeToBytes(z1, l_z1);

    memcpy(bx, priv_key, 32);
    memcpy(bx + 32, z1, 32);

    memset(v, 1, sizeof(v));
    memset(k, 0, sizeof(k));

    memcpy(buf, v, sizeof(v));
    buf[sizeof(v)] = 0x00;
    memcpy(buf + sizeof(v) + 1, bx, 64);
    hmac_sha256(k, sizeof(k), buf, sizeof(buf), k);
    hmac_sha256(k, sizeof(k), v, sizeof(v), v);

    memcpy(buf, v, sizeof(v));
    buf[sizeof(v)] = 0x01;
    memcpy(buf + sizeof(v) + 1, bx, 64);
    hmac_sha256(k, sizeof(k), buf, sizeof(buf), k);
    hmac_sha256(k, sizeof(k), v, sizeof(k), v);

    memset(bx, 0, sizeof(bx));

    for (i = 0; i < 10000; i++) {
        hmac_sha256(k, sizeof(k), v, sizeof(v), secret);
        vli_bytesToNative(l_secret, secret);
        if ( !vli_isZero(l_secret) && vli_cmp(curve_n, l_secret) == 1) {
            return 0; // good number -> no error
        }

        memcpy(buf, v, sizeof(v));
        buf[sizeof(v)] = 0x00;
        hmac_sha256(k, sizeof(k), buf, sizeof(v) + 1, k);
        hmac_sha256(k, sizeof(k), v, sizeof(v), v);
    }
    // we generated 10000 numbers, none of them is good -> fail
    return 1;
}
