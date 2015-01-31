/**
 * Copyright (c) 2013 Tomas Dzetkulic
 * Copyright (c) 2013 Pavol Rusnak
 * Copyright (c) 2015 Douglas J Bakkum
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "ripemd160.h"
#include "random.h"
#include "base58.h"
#include "bignum.h"
#include "sha2.h"
#include "hmac.h"
#include "ecdsa.h"
#include "utils.h"


// cp3 = cp1 + cp2
static void point_add_jacobian(const curve_point_jacobian *CP1, 
                        curve_point_jacobian *CP2)//, 
                        //curve_point_jacobian *CP3)
{
   
    /*
        The "add-2007-bl" 
        Cost: 11M + 5S + 9add + 4*2.
        Cost: 10M + 4S + 9add + 4*2 dependent upon the first point.
        Source: 2007 Bernstein–Lange;
        Explicit formulas:
            Z1Z1 = Z12
            Z2Z2 = Z22
            U1 = X1*Z2Z2
            U2 = X2*Z1Z1
            S1 = Y1*Z2*Z2Z2
            S2 = Y2*Z1*Z1Z1
            H = U2-U1
            I = (2*H)2
            J = H*I
            r = 2*(S2-S1)
            V = U1*I
            X3 = r2-J-2*V
            Y3 = r*(V-X3)-2*S1*J
            Z3 = ((Z1+Z2)2-Z1Z1-Z2Z2)*H

        Three operand forumulas: 
        No assumptions on Z1, Z2 
            Z1Z1 = Z1  * Z1
            Z2Z2 = Z2  * Z2
            U1  =  X1  * Z2Z2
            U2  =  X2  * Z1Z1
            t0  =  Z2  * Z2Z2
            S1  =  Y1  * t0
            t1  =  Z1  * Z1Z1
            S2  =  Y2  * t1
            H   =  U2  - U1
            t2  =  two * H
            I   =  t2  * t2
            J   =  H   * I
            t3  =  S2  - S1
            r   =  two * t3
            V   =  U1  * I
            t4  =  r   * r
            t5  =  two * V
            t6  =  t4  - J
            X3  =  t6  - t5
            t7  =  V   - X3
            t8  =  S1  * J
            t9  =  two * t8
            t10 =  r   * t7
            Y3  =  t10 - t9
            t11 =  Z1  + Z2
            t12 =  t11 * t11
            t13 =  t12 - Z1Z1
            t14 =  t13 - Z2Z2
            Z3  =  t14 * H   
    */
    
    // CP2 equal to zero case
    if (bn_is_zero(&CP2->x) && bn_is_zero(&CP2->y)) {
        memcpy(&CP2->x, &CP1->x, sizeof(bignum256));
        memcpy(&CP2->y, &CP1->y, sizeof(bignum256));
        memcpy(&CP2->z, &CP1->z, sizeof(bignum256));
        return; 
    }

    curve_point_jacobian CP3;
    
    bignum256 Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V,
              t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, 
              t10, t11, t12, t13, t14, two;

    bn_zero(&two);
    bn_addi(&two, 2);

    bn_multiply_res(&CP1->z, &CP1->z, &Z1Z1, &prime256k1);
    bn_multiply_res(&CP2->z, &CP2->z, &Z2Z2, &prime256k1);
    bn_multiply_res(&CP1->x, &Z2Z2, &U1, &prime256k1);
    bn_multiply_res(&CP2->x, &Z1Z1, &U2, &prime256k1);
    bn_multiply_res(&CP2->z, &Z2Z2, &t0, &prime256k1);
    bn_multiply_res(&CP1->y, &t0, &S1, &prime256k1);
    bn_multiply_res(&CP1->z, &Z1Z1, &t1, &prime256k1);
    bn_multiply_res(&CP2->y, &t1, &S2, &prime256k1);
    bn_subtractmod(&U2, &U1, &H, &prime256k1);
    
    bn_multiply_res(&two, &H, &t2, &prime256k1);
    bn_multiply_res(&t2, &t2, &I, &prime256k1);
    bn_multiply_res(&H, &I, &J, &prime256k1);
    bn_subtractmod(&S2 ,&S1 ,&t3, &prime256k1);
    
    bn_multiply_res(&two, &t3, &r, &prime256k1);
    bn_multiply_res(&U1, &I, &V, &prime256k1);
    bn_multiply_res(&r, &r, &t4, &prime256k1);
    bn_multiply_res(&two, &V, &t5, &prime256k1);
    bn_subtractmod(&t4, &J, &t6, &prime256k1);
    bn_subtractmod(&t6, &t5, &CP3.x, &prime256k1);
    bn_subtractmod(&V, &CP3.x, &t7, &prime256k1);
    
    bn_multiply_res(&S1, &J, &t8, &prime256k1);
    bn_multiply_res(&two, &t8, &t9, &prime256k1);
    bn_multiply_res(&r, &t7, &t10, &prime256k1);
    bn_subtractmod(&t10, &t9, &CP3.y, &prime256k1); 
    
    bn_addmod_res(&CP1->z, &CP2->z, &t11, &prime256k1);
    
    bn_multiply_res(&t11, &t11, &t12, &prime256k1);
    bn_subtractmod(&t12, &Z1Z1, &t13, &prime256k1);
    bn_subtractmod(&t13, &Z2Z2, &t14, &prime256k1);
    
    bn_multiply_res(&t14, &H, &CP3.z, &prime256k1);

    memcpy(&CP2->x, &CP3.x, sizeof(bignum256));
    memcpy(&CP2->y, &CP3.y, sizeof(bignum256));
    memcpy(&CP2->z, &CP3.z, sizeof(bignum256));
}


/* not used
// cp3 = cp1 + cp1
static void point_double_jacobian(curve_point_jacobian *CP1)
{
    / *
        "dbl-2009-l" 
        Cost: 2M + 5S + 6add + 1*8 + 3*2 + 1*3.
        Source: 2009.04.01 Lange.
        Explicit formulas:
            A = X12
            B = Y12
            C = B2
            D = 2*((X1+B)2-A-C)
            E = 3*A
            F = E2
            X3 = F-2*D
            Y3 = E*(D-X3)-8*C
            Z3 = 2*Y1*Z1

        Three operand formulas: 
            A  = X1  * X1
            B  = Y1  * Y1
            C  = B   * B
            t0 = X1  + B
            t1 = t0  * t0
            t2 = t1  - A
            t3 = t2  - C
            D  = two * t3
            E  = three * A
            F  = E   * E
            t4 = two * D
            X3 = F   - t4
            t5 = D   - X3
            t6 = eight   * C
            t7 = E   * t5
            Y3 = t7  - t6
            t8 = Y1  * Z1
            Z3 = two * t8
    * /
    
    curve_point_jacobian CP3;
    
    bignum256 A, B, C, t0, t1, t2, t3, D, E, F, 
              t4, t5, t6, t7, t8, two, three, eight;
    
    bn_zero(&two);   bn_addi(&two, 2); 
    bn_zero(&three); bn_addi(&three, 3); 
    bn_zero(&eight); bn_addi(&eight, 8); 

    bn_multiply_res(&CP1->x, &CP1->x, &A, &prime256k1); 
    bn_multiply_res(&CP1->y, &CP1->y, &B, &prime256k1); 
    bn_multiply_res(&B, &B, &C, &prime256k1); 
    bn_addmod_res(&CP1->x, &B, &t0, &prime256k1); 
    
    bn_multiply_res(&t0, &t0, &t1, &prime256k1); 
    bn_subtractmod(&t1, &A, &t2, &prime256k1); 
    bn_subtractmod(&t2, &C, &t3, &prime256k1); 
    
    bn_multiply_res(&two, &t3, &D, &prime256k1 ); 
    bn_multiply_res(&three, &A, &E, &prime256k1 ); 
    bn_multiply_res(&E, &E, &F, &prime256k1 ); 
    bn_multiply_res(&two, &D, &t4, &prime256k1); 
    bn_subtractmod(&F, &t4,  &CP3.x, &prime256k1); 
    bn_subtractmod(&D, &CP3.x, &t5, &prime256k1); 
    
    bn_multiply_res(&eight, &C, &t6, &prime256k1); 
    bn_multiply_res(&E, &t5, &t7, &prime256k1); 
    bn_subtractmod(&t7, &t6, &CP3.y, &prime256k1); 
    
    bn_multiply_res(&CP1->y, &CP1->z, &t8, &prime256k1); 
    bn_multiply_res(&two, &t8, &CP3.z, &prime256k1); 
    
    memcpy(&CP1->x, &CP3.x, sizeof(bignum256));
    memcpy(&CP1->y, &CP3.y, sizeof(bignum256));
    memcpy(&CP1->z, &CP3.z, sizeof(bignum256));
}
*/

static void point_jacobian_to_xy(const curve_point_jacobian *J, curve_point *P)
{
    // Set U=1/Jz, then Px = Jx*U^2 and Py = Jy*U^3 (one modinv instead of two)
    bignum256 U, UU, UUU, Z;
    memcpy(&Z, &J->z, sizeof(bignum256));

    bn_inverse(&Z, &prime256k1); 
    memcpy(&U, &Z, sizeof(bignum256));

    bn_multiply_res(&U, &U, &UU, &prime256k1);
    bn_multiply_res(&UU, &U,&UUU, &prime256k1);
    
    bn_multiply_res(&J->x, &UU, &P->x, &prime256k1);
    bn_multiply_res(&J->y, &UUU, &P->y, &prime256k1);
}


// Set cp2 = cp1
void point_copy(const curve_point *cp1, curve_point *cp2)
{
	memcpy(&(cp2->x),  &(cp1->x), sizeof(bignum256));
	memcpy(&(cp2->y),  &(cp1->y), sizeof(bignum256));
}


// cp2 = cp1 + cp2
void point_add(const curve_point *cp1, curve_point *cp2)
{
	int i;
	uint32_t temp;
	bignum256 lambda, inv, xr, yr;

	if (point_is_infinity(cp1)) {
		return;
	}
	if (point_is_infinity(cp2)) {
		point_copy(cp1, cp2);
		return;
	}
	if (point_is_equal(cp1, cp2)) {
		point_double(cp2);
		return;
	}
	if (point_is_negative_of(cp1, cp2)) {
		point_set_infinity(cp2);
		return;
	}

	bn_subtract(&(cp2->x), &(cp1->x), &inv);
	bn_inverse(&inv, &prime256k1);
	bn_subtract(&(cp2->y), &(cp1->y), &lambda);
	bn_multiply(&inv, &lambda, &prime256k1);
	memcpy(&xr, &lambda, sizeof(bignum256));
	bn_multiply(&xr, &xr, &prime256k1);
	temp = 0;
	for (i = 0; i < 9; i++) {
		temp += xr.val[i] + 3u * prime256k1.val[i] - cp1->x.val[i] - cp2->x.val[i];
		xr.val[i] = temp & 0x3FFFFFFF;
		temp >>= 30;
	}
	bn_fast_mod(&xr, &prime256k1);
	bn_subtract(&(cp1->x), &xr, &yr);
	// no need to fast_mod here
	// bn_fast_mod(&yr);
	bn_multiply(&lambda, &yr, &prime256k1);
	bn_subtract(&yr, &(cp1->y), &yr);
	bn_fast_mod(&yr, &prime256k1);
	memcpy(&(cp2->x), &xr, sizeof(bignum256));
	memcpy(&(cp2->y), &yr, sizeof(bignum256));
	bn_mod(&(cp2->x), &prime256k1);
	bn_mod(&(cp2->y), &prime256k1);
}

// cp = cp + cp
void point_double(curve_point *cp)
{
	int i;
	uint32_t temp;
	bignum256 lambda, inverse_y, xr, yr;

	if (point_is_infinity(cp)) {
		return;
	}
	if (bn_is_zero(&(cp->y))) {
		point_set_infinity(cp);
		return;
	}

	memcpy(&inverse_y, &(cp->y), sizeof(bignum256));
	bn_inverse(&inverse_y, &prime256k1);
	memcpy(&lambda, &three_over_two256k1, sizeof(bignum256));
	bn_multiply(&inverse_y, &lambda, &prime256k1);
	bn_multiply(&(cp->x), &lambda, &prime256k1);
	bn_multiply(&(cp->x), &lambda, &prime256k1);
	memcpy(&xr, &lambda, sizeof(bignum256));
	bn_multiply(&xr, &xr, &prime256k1);
	temp = 0;
	for (i = 0; i < 9; i++) {
		temp += xr.val[i] + 3u * prime256k1.val[i] - 2u * cp->x.val[i];
		xr.val[i] = temp & 0x3FFFFFFF;
		temp >>= 30;
	}
	bn_fast_mod(&xr, &prime256k1);
	bn_subtract(&(cp->x), &xr, &yr);
	// no need to fast_mod here
	// bn_fast_mod(&yr);
	bn_multiply(&lambda, &yr, &prime256k1);
	bn_subtract(&yr, &(cp->y), &yr);
	bn_fast_mod(&yr, &prime256k1);
	memcpy(&(cp->x), &xr, sizeof(bignum256));
	memcpy(&(cp->y), &yr, sizeof(bignum256));
	bn_mod(&(cp->x), &prime256k1);
	bn_mod(&(cp->y), &prime256k1);
    memset(&inverse_y,0,sizeof(bignum256));
    memset(&lambda,0,sizeof(bignum256));
    memset(&xr,0,sizeof(bignum256));
    memset(&yr,0,sizeof(bignum256));
}

// res = k * p
void point_multiply(const bignum256 *k, const curve_point *p, curve_point *res)
{
	int i, j;
	// result is zero
	int is_zero = 1;
	curve_point curr;
	// initial res
	memcpy(&curr, p, sizeof(curve_point));
	for (i = 0; i < 9; i++) {
		for (j = 0; j < 30; j++) {
			if (i == 8 && (k->val[i] >> j) == 0) break;
			if (k->val[i] & (1u << j)) {
				if (is_zero) {
					memcpy(res, &curr, sizeof(curve_point));
					is_zero = 0;
				} else {
					point_add(&curr, res);
				}
			}
			point_double(&curr);
		}
	}
    memset(&curr,0,sizeof(curve_point));
}

// set point to internal representation of point at infinity
void point_set_infinity(curve_point *p)
{
	bn_zero(&(p->x));
	bn_zero(&(p->y));
}

// return true iff p represent point at infinity
// both coords are zero in internal representation
int point_is_infinity(const curve_point *p)
{
	return bn_is_zero(&(p->x)) && bn_is_zero(&(p->y));
}

// return true iff both points are equal
int point_is_equal(const curve_point *p, const curve_point *q)
{
	return bn_is_equal(&(p->x), &(q->x)) && bn_is_equal(&(p->y), &(q->y));
}

// returns true iff p == -q
// expects p and q be valid points on curve other than point at infinity
int point_is_negative_of(const curve_point *p, const curve_point *q)
{
	// if P == (x, y), then -P would be (x, -y) on this curve
	if (!bn_is_equal(&(p->x), &(q->x))) {
		return 0;
	}
	
	// we shouldn't hit this for a valid point
	if (bn_is_zero(&(p->y))) {
		return 0;
	}
	
	return !bn_is_equal(&(p->y), &(q->y));
}


// Avoid side-channel attacks
// use double-and-add-always
// balance power consumption
// randomize double-and-add order (makes above 2 not necessary?)
// Jacobian coordinates
// C = k * G  
void scalar_multiply_jacobian(const bignum256 *k, curve_point *C)
{
    curve_point_jacobian sham, kG, curr;
	int i, j;

#if USE_RANDOM_ORDER_MULT
    random_init();
    int r[256];
    for (i = 0; i < 256; i++) {
        r[i] = i;
    }
    random_shuffle(r, 256);
#endif
    
    // initializations
    bn_zero(&kG.x);
    bn_zero(&kG.y);
    bn_one(&kG.z);
    
    bn_zero(&sham.x);
    bn_zero(&sham.y);
    bn_one(&sham.z);
	
	memcpy(&curr.x, &G256k1.x, sizeof(bignum256));
	memcpy(&curr.y, &G256k1.y, sizeof(bignum256));
    bn_one(&curr.z);
   


	for (i = 0; i < 256; i++) {
#if USE_RANDOM_ORDER_MULT
        j = r[i];
#else
        j = i;
#endif
        memcpy(&curr, secp256k1_cp + j, sizeof(curve_point));
        if (k->val[j / 30] & (1u << (j % 30))) {
            point_add_jacobian(&curr, &kG);
        } else {
            point_add_jacobian(&curr, &sham);
        }
    }
    point_jacobian_to_xy(&kG, C);
}


void uncompress_coords(uint8_t odd, const bignum256 *x, bignum256 *y)
{
    // y^2 = x^3 + 0*x + 7
    memcpy(y, x, sizeof(bignum256));       // y is x
    bn_multiply(x, y, &prime256k1);        // y is x^2
    bn_multiply(x, y, &prime256k1);        // y is x^3
    bn_addmodi(y, 7, &prime256k1);         // y is x^3 + 7
    bn_sqrt(y, &prime256k1);               // y = sqrt(y)
    if ((odd & 0x01) != (y->val[0] & 1)) {
        bn_subtract_noprime(&prime256k1, y, y);   // y = -y
    }
}


static void reverse_hex(char *h, int len)
{
    char copy[len];
    strncpy(copy, h, len);
    int i;
    for (i = 0; i<len; i += 2) {
        h[i] = copy[len - i - 2];
        h[i + 1] = copy[len - i - 1];
    }   
}

static void varint(char * vi, uint64_t i)
{
    memset(vi, 0, LENVARINT); 
    int len = 0;
    char v[LENVARINT];  
    if( i<0xfd ){
        sprintf(v, "%02llx", i);
    } else if (i<=0xffff) {
        sprintf(v, "%04llx", i);
        sprintf(vi, "fd");
        len = 4;
    
    } else if (i<=0xffffffff) {
        sprintf(v, "%08llx", i);
        sprintf(vi, "fe");
        len = 8;

    } else {
        sprintf(v, "%016llx", i);
        sprintf(vi, "ff");
        len = 16;
    }
  
    // reverse order
    if (len) {
        reverse_hex(v, len); 
        strncat(vi, v, len);
    } else {
        strncpy(vi, v, 2);
    }
}

static int message_magic(const char * msg, int msg_len, char * out)
{
    const char *header = "\030Bitcoin Signed Message:\n";
    uint64_t vilen = strlen(msg); 
    char vi[LENVARINT];
    varint(vi, vilen);
    
    memcpy(out, header, strlen(header));
    memcpy(out + strlen(header), hex_to_uint8(vi), strlen(vi)/2);
    memcpy(out + strlen(header) + strlen(vi)/2, msg, msg_len);
    
    int outlen = strlen(header)+strlen(msg)+strlen(vi)/2;
    return outlen;
}


static int verify_message(const uint8_t * sig_m, const char * msg, int msg_len, const uint8_t * pubkey)
{
    uint8_t r[32], s[32], h[32], Qxy[64], odd;
    uint8_t nV = sig_m[0];
    uint32_t recid;
    bignum256 bn_x, bn_y, bn_r, bn_s, bn_recid, bn_e;
    curve_point res, Q, R;  
    
    if (nV < 27 || nV > 30) {
        return 1;
    }
    recid = nV - 27;
    odd = recid % 2; 
    
    memcpy(r, sig_m + 1, 32);
    memcpy(s, sig_m + 33, 32);
    
    // x = r + (recid/2) * order
    bn_read_be(r, &bn_r);
    bn_read_be(s, &bn_s);
    bn_zero(&bn_recid);
    bn_addi(&bn_recid, recid / 2);
    bn_multiply(&order256k1, &bn_recid, &order256k1);// necessary?  
    bn_addmod(&bn_recid, &bn_r, &order256k1);
    memcpy(&bn_x, &bn_recid, sizeof(bignum256));

    uncompress_coords(odd, &bn_x, &bn_y);

    memcpy(&R.x, &bn_x, sizeof(bignum256)); 
    memcpy(&R.y, &bn_y, sizeof(bignum256)); 

    sha256_Raw((uint8_t *)msg, msg_len, h);
    sha256_Raw(h, 32, h);
    bn_read_be(h, &bn_e);
    bn_subtract_noprime(&order256k1, &bn_e, &bn_e);   // e = -e
    bn_mod(&bn_e, &order256k1);
    
    // Q = r^-1 (sR - eG)
    point_multiply(&bn_s, &R, &res);
    point_multiply(&bn_e, &G256k1, &Q);
    point_add(&res, &Q);
    bn_inverse(&bn_r, &order256k1);
    point_multiply(&bn_r, &Q, &Q);
    
    bn_write_be(&Q.x, Qxy);
    bn_write_be(&Q.y, Qxy + 32);

    return memcmp(Qxy, pubkey, 64); // success when Q == public key
}


int ecdsa_sign_message(const uint8_t *priv_key, const char *msg, uint32_t msg_len, uint8_t *sig_m)
{
    int ret;
    char nV = 27;
    char msg_m[msg_len + LENVARINT + 64];
    int msg_m_len = message_magic(msg, msg_len, msg_m); 
    uint8_t public_key[64];
    uint8_t sig[64];
    
    ret = ecdsa_sign_double(priv_key, (uint8_t *)msg_m, msg_m_len, sig); 
    ecdsa_get_public_key64(priv_key, public_key);
   
    if (!ret) {
        memcpy(sig_m+1, sig, 64);
        do {
            // Using tests_unit.c:tests_sign_message() to generate (alot of) 
            // surrogate data, nV never exceeded 28...
            sig_m[0] = nV;
            ret = verify_message(sig_m, msg_m, msg_m_len, public_key); 
            nV++;
        }
        while (ret && nV < 31);
    }
    return ret;
}



// generate K in a deterministic way, according to RFC6979
// http://tools.ietf.org/html/rfc6979
int generate_k_rfc6979(bignum256 *secret, const uint8_t *priv_key, const uint8_t *hash)
{
	int i;
	uint8_t v[32], k[32], bx[2*32], buf[32 + 1 + sizeof(bx)], t[32];
	bignum256 z1;

	memcpy(bx, priv_key, 32);
	bn_read_be(hash, &z1);
	bn_mod(&z1, &order256k1);
	bn_write_be(&z1, bx + 32);

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

    memset(bx,0,sizeof(bx));
    memset(&z1,0,sizeof(bignum256));

	for (i = 0; i < 10000; i++) {
		hmac_sha256(k, sizeof(k), v, sizeof(v), t);
		bn_read_be(t, secret);
		if ( !bn_is_zero(secret) && bn_is_less(secret, &order256k1) ) {
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

int ecdsa_sign(const uint8_t *priv_key, const uint8_t *msg, uint32_t msg_len, uint8_t *sig)
{
	uint8_t hash[32];
	sha256_Raw(msg, msg_len, hash);
	return ecdsa_sign_digest(priv_key, hash, sig);
}

int ecdsa_sign_double(const uint8_t *priv_key, const uint8_t *msg, uint32_t msg_len, uint8_t *sig)
{
	uint8_t hash[32];
	sha256_Raw(msg, msg_len, hash);
	sha256_Raw(hash, 32, hash);
	return ecdsa_sign_digest(priv_key, hash, sig);
}

// uses secp256k1 curve
// priv_key is a 32 byte big endian stored number
// sig is 64 bytes long array for the signature
// digest is 32 bytes of digest
int ecdsa_sign_digest(const uint8_t *priv_key, const uint8_t *digest, uint8_t *sig)
{
	uint32_t i;
	curve_point R;
	bignum256 k, z;
	bignum256 *da = &R.y;

	bn_read_be(digest, &z);

	// generate K deterministically
    if (generate_k_rfc6979(&k, priv_key, digest) != 0) {
		return 1;
	}

	// compute k*G
	scalar_multiply_jacobian(&k, &R);
    
    // r = (rx mod n)
	bn_mod(&R.x, &order256k1);
	// if r is zero, we fail
	if (bn_is_zero(&R.x)) return 2;
	bn_inverse(&k, &order256k1);
	bn_read_be(priv_key, da);
	bn_multiply(&R.x, da, &order256k1);
	for (i = 0; i < 8; i++) {
		da->val[i] += z.val[i];
		da->val[i + 1] += (da->val[i] >> 30);
		da->val[i] &= 0x3FFFFFFF;
	}
	da->val[8] += z.val[8];
	bn_multiply(da, &k, &order256k1);
	bn_mod(&k, &order256k1);
	// if k is zero, we fail
	if (bn_is_zero(&k)) return 3;

	// if S > order/2 => S = -S
	if (bn_is_less(&order256k1_half, &k)) {
		bn_subtract_noprime(&order256k1, &k, &k);
	}

	// we are done, R.x and k is the result signature
	bn_write_be(&R.x, sig);
	bn_write_be(&k, sig + 32);

	return 0;
}

void ecdsa_get_public_key33(const uint8_t *priv_key, uint8_t *pub_key)
{
	curve_point R;
	bignum256 k;

	bn_read_be(priv_key, &k);
	// compute k*G
	scalar_multiply_jacobian(&k, &R);
	pub_key[0] = 0x02 | (R.y.val[0] & 0x01);
	bn_write_be(&R.x, pub_key + 1);
    
    memset(&R,0,sizeof(curve_point));
    memset(&k,0,sizeof(bignum256));
}

void ecdsa_get_public_key65(const uint8_t *priv_key, uint8_t *pub_key)
{
	curve_point R;
	bignum256 k;

	bn_read_be(priv_key, &k);
	// compute k*G
	scalar_multiply_jacobian(&k, &R);
	pub_key[0] = 0x04;
	bn_write_be(&R.x, pub_key + 1);
	bn_write_be(&R.y, pub_key + 33);
    
    memset(&R,0,sizeof(curve_point));
    memset(&k,0,sizeof(bignum256));
}

void ecdsa_get_public_key64(const uint8_t *priv_key, uint8_t *pub_key)
{
	curve_point R;
	bignum256 k;

	bn_read_be(priv_key, &k);
	// compute k*G
	scalar_multiply_jacobian(&k, &R);
	bn_write_be(&R.x, pub_key);
	bn_write_be(&R.y, pub_key + 32);
    
    memset(&R,0,sizeof(curve_point));
    memset(&k,0,sizeof(bignum256));
}

int ecdsa_verify(const uint8_t *pub_key, const uint8_t *sig, const uint8_t *msg, uint32_t msg_len)
{
	uint8_t hash[32];
	sha256_Raw(msg, msg_len, hash);
	return ecdsa_verify_digest(pub_key, sig, hash);
}

int ecdsa_verify_double(const uint8_t *pub_key, const uint8_t *sig, const uint8_t *msg, uint32_t msg_len)
{
	uint8_t hash[32];
	sha256_Raw(msg, msg_len, hash);
	sha256_Raw(hash, 32, hash);
	return ecdsa_verify_digest(pub_key, sig, hash);
}

// returns 0 if verification succeeded
int ecdsa_verify_digest(const uint8_t *pub_key, const uint8_t *sig, const uint8_t *digest)
{
	int i, j;
	curve_point pub, res;
	bignum256 r, s, z;

	if (!ecdsa_read_pubkey(pub_key, &pub)) {
		return 1;
	}

	bn_read_be(sig, &r);
	bn_read_be(sig + 32, &s);

	bn_read_be(digest, &z);

	if (bn_is_zero(&r) || bn_is_zero(&s) ||
	    (!bn_is_less(&r, &order256k1)) ||
	    (!bn_is_less(&s, &order256k1))) return 2;

	bn_inverse(&s, &order256k1); // s^-1
	bn_multiply(&s, &z, &order256k1); // z*s^-1
	bn_mod(&z, &order256k1);
	bn_multiply(&r, &s, &order256k1); // r*s^-1
	bn_mod(&s, &order256k1);
	if (bn_is_zero(&z)) {
		// our message hashes to zero
		// I don't expect this to happen any time soon
		return 3;
	} else {
		scalar_multiply_jacobian(&z, &res);
	}

	// both pub and res can be infinity, can have y = 0 OR can be equal -> false negative
	for (i = 0; i < 9; i++) {
		for (j = 0; j < 30; j++) {
			if (i == 8 && (s.val[i] >> j) == 0) break;
			if (s.val[i] & (1u << j)) {
				point_add(&pub, &res);
			}
			point_double(&pub);
		}
	}

	bn_mod(&(res.x), &order256k1);

	// signature does not match
	if (!bn_is_equal(&res.x, &r)) return 5;

	// all OK
	return 0;
}


void ecdsa_get_pubkeyhash(const uint8_t *pub_key, uint8_t *pubkeyhash)
{
	uint8_t h[32];
	if (pub_key[0] == 0x04) {  // uncompressed format
		sha256_Raw(pub_key, 65, h);
	} else if (pub_key[0] == 0x00) { // point at infinity
		sha256_Raw(pub_key, 1, h);
	} else {
		sha256_Raw(pub_key, 33, h); // expecting compressed format
	}
	ripemd160(h, 32, pubkeyhash);
}


void ecdsa_get_address_raw(const uint8_t *pub_key, uint8_t version, uint8_t *addr_raw)
{
	addr_raw[0] = version;
	ecdsa_get_pubkeyhash(pub_key, addr_raw + 1);
}


void ecdsa_get_address(const uint8_t *pub_key, uint8_t version, char *addr, int addrsize)
{
	uint8_t raw[21];
	ecdsa_get_address_raw(pub_key, version, raw);
	base58_encode_check(raw, 21, addr, addrsize);
}


void ecdsa_get_wif(const uint8_t *priv_key, uint8_t version, char *wif, int wifsize)
{
	uint8_t data[34];
	data[0] = version;
	memcpy(data + 1, priv_key, 32);
	data[33] = 0x01;
	base58_encode_check(data, 34, wif, wifsize);
}


int ecdsa_address_decode(const char *addr, uint8_t *out)
{
	if (!addr) return 0;
	return base58_decode_check(addr, out, 21) == 21;
}


int ecdsa_read_pubkey(const uint8_t *pub_key, curve_point *pub)
{
	if (pub_key[0] == 0x04) {
		bn_read_be(pub_key + 1, &(pub->x));
		bn_read_be(pub_key + 33, &(pub->y));
#if USE_PUBKEY_VALIDATE
		return ecdsa_validate_pubkey(pub);
#else
		return 1;
#endif
	}
	if (pub_key[0] == 0x02 || pub_key[0] == 0x03) { // compute missing y coords
		bn_read_be(pub_key + 1, &(pub->x));
		uncompress_coords(pub_key[0], &(pub->x), &(pub->y));
#if USE_PUBKEY_VALIDATE
		return ecdsa_validate_pubkey(pub);
#else
		return 1;
#endif
	}
	// error
	return 0;
}


// Verifies that:
//   - pub is not the point at infinity.
//   - pub->x and pub->y are in range [0,p-1].
//   - pub is on the curve.
//   - n*pub is the point at infinity.
int ecdsa_validate_pubkey(const curve_point *pub)
{
	bignum256 y_2, x_3_b;
	curve_point temp;

	if (point_is_infinity(pub)) {
		return 0;
	}

	if (!bn_is_less(&(pub->x), &prime256k1) || !bn_is_less(&(pub->y), &prime256k1)) {
		return 0;
	}

	memcpy(&y_2, &(pub->y), sizeof(bignum256));
	memcpy(&x_3_b, &(pub->x), sizeof(bignum256));

	// y^2
	bn_multiply(&(pub->y), &y_2, &prime256k1);
	bn_mod(&y_2, &prime256k1);

	// x^3 + b
	bn_multiply(&(pub->x), &x_3_b, &prime256k1);
	bn_multiply(&(pub->x), &x_3_b, &prime256k1);
	bn_addmodi(&x_3_b, 7, &prime256k1);

	if (!bn_is_equal(&x_3_b, &y_2)) {
		return 0;
	}

	point_multiply(&order256k1, pub, &temp);

	if (!point_is_infinity(&temp)) {
		return 0;
	}

	return 1;
}


int ecdsa_sig_to_der(const uint8_t *sig, uint8_t *der)
{
	int i;
	uint8_t *p = der, *len, *len1, *len2;
	*p = 0x30; p++;                        // sequence
	*p = 0x00; len = p; p++;               // len(sequence)

	*p = 0x02; p++;                        // integer
	*p = 0x00; len1 = p; p++;              // len(integer)

	// process R
	i = 0;
	while (sig[i] == 0 && i < 32) { i++; } // skip leading zeroes
	if (sig[i] >= 0x80) { // put zero in output if MSB set
		*p = 0x00; p++; *len1 = *len1 + 1;
	}
	while (i < 32) { // copy bytes to output
		*p = sig[i]; p++; *len1 = *len1 + 1; i++;
	}

	*p = 0x02; p++;                        // integer
	*p = 0x00; len2 = p; p++;              // len(integer)

	// process S
	i = 32;
	while (sig[i] == 0 && i < 64) { i++; } // skip leading zeroes
	if (sig[i] >= 0x80) { // put zero in output if MSB set
		*p = 0x00; p++; *len2 = *len2 + 1;
	}
	while (i < 64) { // copy bytes to output
		*p = sig[i]; p++; *len2 = *len2 + 1; i++;
	}

	*len = *len1 + *len2 + 4;
	return *len + 2;

}



