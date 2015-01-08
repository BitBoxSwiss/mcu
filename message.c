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



#include "message.h"
#include "sha2.h"
#include "utils.h"
#include "ecdsa.h"
#include "secp256k1.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>


static void reverse_hex(char * h, int len)
{
    char copy[len];
    strncpy(copy,h,len);
    int i;
    for( i=0; i<len; i+=2 ){
        h[i]   = copy[len-i-2];
        h[i+1] = copy[len-i-1];
    }   
}

static void varint( char * vi, uint64_t i)
{
    memset(vi,0,LENVARINT); 
    int len=0;
    char v[LENVARINT];  
    if( i<0xfd ){
        sprintf(v,"%02llx",i);
    } else if( i<=0xffff ){
        sprintf(v, "%04llx",i);
        sprintf(vi,"fd");
        len = 4;
    
    } else if( i<=0xffffffff ){
        sprintf(v, "%08llx",i);
        sprintf(vi,"fe");
        len = 8;

    } else {
        sprintf(v, "%016llx",i);
        sprintf(vi,"ff");
        len = 16;
    }
  
    // reverse order
    if( len ){
        reverse_hex(v,len); 
        strncat(vi,v,len);
    } else {
        strncpy(vi,v,2);
    }
}


static int message_magic(const char * msg, int msg_len, char * out)
{
    const char * header = "\030Bitcoin Signed Message:\n";
    
    uint64_t vilen = strlen(msg); 
    char vi[LENVARINT];
    varint( vi, vilen);
    
    memcpy(out,header,strlen(header));
    memcpy(out+strlen(header),hex_to_uint8(vi),strlen(vi)/2);
    memcpy(out+strlen(header)+strlen(vi)/2,msg,msg_len);
    
    int outlen = strlen(header)+strlen(msg)+strlen(vi)/2;
    return outlen;
}




static int verify_message( const uint8_t * sig_m, const char * msg, int msg_len, const uint8_t * pubkey )
{

    uint8_t r[32];
    uint8_t s[32];
    uint8_t nV = sig_m[0];
    memcpy(r,sig_m+1,32);
    memcpy(s,sig_m+33,32);


    if( nV < 27 || nV > 30){
        return -1;
    }
    
    uint32_t recid = nV - 27;
    
    // # 1.1
    // x = r + (recid/2) * order
    bignum256 bn_x, bn_y, bn_r, bn_s, bn_recid;
    bn_read_be(r, &bn_r);
    bn_read_be(s, &bn_s);
    bn_zero(&bn_recid);
    bn_addi(&bn_recid,recid/2);
    bn_multiply(&order256k1_half, &bn_recid, &order256k1); // TODO check - recid/2 <-> order256k1_half - should divide by 2 only once
    bn_addmod(&bn_recid, &bn_r, &order256k1);
    
    memcpy(&bn_x, &bn_recid, sizeof(bignum256));


    uint8_t odd = recid%2; // TODO check if correct 
    
    uncompress_coords(odd, &bn_x, &bn_y);


    curve_point R;  
    memcpy(&R.x,&bn_x,sizeof(bignum256)); 
    memcpy(&R.y,&bn_y,sizeof(bignum256)); 

    uint8_t h[32];
    bignum256 bn_e;
    sha256_Raw((uint8_t *)msg, msg_len, h);
    sha256_Raw(h, 32, h);
    bn_read_be(h, &bn_e);
    bn_substract_noprime(&order256k1, &bn_e, &bn_e);   // e = -e
    bn_mod(&bn_e, &order256k1);
    
    // Q = r^-1 (sR - eG)
    curve_point res, Q;
    point_multiply(&bn_s,&R,&res); //  sR 
    point_multiply(&bn_e,&G256k1,&Q);   // -eG
    point_add(&res,&Q); // sR-eG
    bn_inverse(&bn_r, &order256k1);
    point_multiply(&bn_r,&Q,&Q); //  Q = r^-1 (sR - eG) 
    
    uint8_t Qxy[64];
    bn_write_be( &Q.x, Qxy);
    bn_write_be( &Q.y, Qxy+32);

    return memcmp(Qxy,pubkey,64); // 0 on success when Q == public key
}

int sign_message( const uint8_t *priv_key, const char *msg, uint32_t msg_len, uint8_t *sig_m )
{
    int ret;
    char msg_m[msg_len+LENVARINT+64];
    int msg_m_len = message_magic(msg, msg_len, msg_m); 
    uint8_t public_key[64];
    uint8_t sig[64];
    char nV = 27;
    
    ret = ecdsa_sign_double( priv_key, (uint8_t *)msg_m, msg_m_len, sig ); // 0 on success 
    ecdsa_get_public_key64(priv_key, public_key);
   
    if( !ret ){
        memcpy(sig_m+1,sig,64);
        do{
            sig_m[0] = nV++;
            ret = verify_message(sig_m,msg_m,msg_m_len,public_key); // 0 on success
        }
        while( ret && nV<36 ); // TEST for different nV
    }
    return ret; // 0 on success
}




