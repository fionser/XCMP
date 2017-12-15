/*
        libgm - A library implementing the Goldwasser–Micali cryptosystem.

        Copyright (C) 2012 Praveen Kumar (areteix@gmail.com)

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.
            
        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.
                            
        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "gm.h"

void init_rand_gm( gmp_randstate_t rand, 
                   gm_get_rand_t get_rand, 
                   int bytes )
{
    void* buf;
    mpz_t s;

    buf = malloc(bytes);
    get_rand(buf, bytes);

    gmp_randinit_default(rand);
    mpz_init(s);
    mpz_import(s, bytes, 1, 1, 0, 0, buf);
    gmp_randseed(rand, s);
    mpz_clear(s);

    free(buf);
}


void gm_keygen( int modulusbits,
                gm_pubkey_t** pub,
                gm_prvkey_t** prv,
                gm_get_rand_t get_rand )
{
    mpz_t p;
    mpz_t q;
    mpz_t pminusone;
    mpz_t qminusone;
    mpz_t pminusoneby2;
    mpz_t qminusoneby2;
    mpz_t resp;
    mpz_t resq;
    mpz_t x;
    gmp_randstate_t rand;

    /* allocate the new key structures */

    *pub = (gm_pubkey_t*) malloc(sizeof(gm_pubkey_t));
    *prv = (gm_prvkey_t*) malloc(sizeof(gm_prvkey_t));

    /* initialize the integers */

    mpz_init((*pub)->x);
    mpz_init((*pub)->n);
    mpz_init((*prv)->p);
    mpz_init((*prv)->q);
    mpz_init((*prv)->pminusoneby2);
    mpz_init((*prv)->qminusoneby2);

    mpz_init(p);
    mpz_init(q);
    mpz_init(pminusone);
    mpz_init(qminusone);
    mpz_init(pminusoneby2);
    mpz_init(qminusoneby2);
    mpz_init(resp);
    mpz_init(resq);
    mpz_init(x);

    /* pick random (modulusbits/2)-bit primes p and q */

    init_rand_gm(rand, get_rand, modulusbits / 8 + 1);
    do
    {
        do
        {
            mpz_urandomb(p, rand, modulusbits / 2);
        } while( !mpz_probab_prime_p(p, 10) );

        do
        {
            mpz_urandomb(q, rand, modulusbits / 2);
        } while( !mpz_probab_prime_p(q, 10) );

        /* compute the public modulus n = p q */
        mpz_mul((*pub)->n, p, q);

    } while( !mpz_tstbit((*pub)->n, modulusbits - 1) );

    mpz_sub_ui(pminusone, p, 1);
    mpz_sub_ui(qminusone, q, 1);
    mpz_div_ui(pminusoneby2, pminusone, 2);
    mpz_div_ui(qminusoneby2, qminusone, 2);

    do
    {
        mpz_urandomb(x, rand, modulusbits);
        mpz_powm(resp, x, pminusoneby2, p);
        mpz_powm(resq, x, qminusoneby2, q);
    } while(mpz_cmp(x,(*pub)->n)>=0 || 
            mpz_cmp_ui(resp, 1)==0 || 
            mpz_cmp_ui(resq, 1)==0);

    /* Store the public and the private keys */
    mpz_set((*prv)->p, p);
    mpz_set((*prv)->q, q);
    mpz_set((*prv)->pminusoneby2, pminusoneby2);
    mpz_set((*prv)->qminusoneby2, qminusoneby2);
    mpz_set((*pub)->x, x);
    (*pub)->bits = modulusbits;

    /* clear temporary integers and rand */
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(pminusone);
    mpz_clear(qminusone);
    mpz_clear(pminusoneby2);
    mpz_clear(qminusoneby2);
    mpz_clear(resp);
    mpz_clear(resq);
    mpz_clear(x);
    gmp_randclear(rand);
    return;
}



gm_ciphertext_t* gm_enc_bit( gm_ciphertext_t* res,
                         gm_pubkey_t* pub,
                         int bit,
                         gm_get_rand_t get_rand )
{
    mpz_t r;
    gmp_randstate_t rand;

    /* pick random blinding factor */

    mpz_init(r);
    init_rand_gm(rand, get_rand, pub->bits / 8 + 1);
    do
    {
        mpz_urandomb(r, rand, pub->bits);
    } while( mpz_cmp(r, pub->n) >= 0 );

    /* compute ciphertext */

    if( !res )
    {
        res = (gm_ciphertext_t*) malloc(sizeof(gm_ciphertext_t));
        mpz_init(res->c);
    }

    mpz_mul(res->c, r, r);
    mpz_mod(res->c, res->c, pub->n);

    if(bit == 1)
    {
        mpz_mul(res->c, res->c, pub->x);
        mpz_mod(res->c, res->c, pub->n);
    }

    mpz_clear(r);
    gmp_randclear(rand);

    return res;
}



gm_ciphertext_t** gm_enc(gm_plaintext_t* input, int* len, gm_pubkey_t* pub)
{
    int i, rem_bit, pos=0;
    gm_ciphertext_t** cipher = NULL;
    mpz_t rem_mp;
    gm_ciphertext_t* ct_buffer[1024];
    gm_plaintext_t* plain;

    *len = 0;
    mpz_init(rem_mp);
    plain = (gm_plaintext_t*) malloc(sizeof(gm_plaintext_t));
    mpz_init_set(plain->m, input->m);

    while(mpz_sgn(plain->m) > 0) 
    { 
        mpz_fdiv_r_2exp(rem_mp, plain->m, 1);
        mpz_fdiv_q_2exp(plain->m, plain->m, 1);
        rem_bit = mpz_get_ui(rem_mp);
        
        ct_buffer[(*len)%1024] = gm_enc_bit(NULL, pub, rem_bit, gm_get_rand_devurandom);
        (*len)++;
        if((*len)%1024 == 0)
        {
            if(cipher != NULL)
            {
                pos += 1024;
                cipher = (gm_ciphertext_t**)realloc(cipher, ((pos+1024)*sizeof(gm_ciphertext_t*)));
            }
            else
            {
                cipher = (gm_ciphertext_t**)malloc(1024 * sizeof(gm_ciphertext_t*));
                pos = 0;
            }
            for(i=0; i<1024; i++)
            {
                cipher[pos+i] = ct_buffer[i];
            }
         }
    }

    if(cipher != NULL)
    {
        pos += 1024;
        cipher = (gm_ciphertext_t**) realloc(cipher, (pos+(*len)%1024) * sizeof(gm_ciphertext_t*));
    }
    else
    {
        cipher = (gm_ciphertext_t**)malloc((*len) * sizeof(gm_ciphertext_t*));
    }
    for(i=0; i<(*len)%1024; i++)
    {
        cipher[pos+i] = ct_buffer[i];
    }
    for(i=0;i<(*len)/2;i++)
    {
        ct_buffer[0] = cipher[i];
        cipher[i] = cipher[(*len)-1-i];
        cipher[(*len)-1-i] = ct_buffer[0];
    }
    gm_freeplaintext(plain);
    return cipher;
}


int gm_dec_bit( gm_prvkey_t* prv, gm_ciphertext_t* ct )
{
    int dec = 0;
    mpz_t t;
    mpz_init(t);

    mpz_powm(t, ct->c, prv->pminusoneby2, prv->p);
    if(mpz_cmp_ui(t, 1) != 0)
    {
        dec = 1;
    }

    mpz_powm(t, ct->c, prv->qminusoneby2, prv->q);
    if(mpz_cmp_ui(t, 1) != 0)
    {
        dec = 1;
    }

    mpz_clear(t);
    return dec;
}



gm_plaintext_t* gm_dec(gm_ciphertext_t** cipher, int len, gm_prvkey_t* prv)
{
    int i, dec_bit;
    gm_plaintext_t* plain = gm_plaintext_from_ui(0);
    for(i=0;i<len;i++)
    {
        dec_bit = gm_dec_bit(prv, cipher[i]);
        if(dec_bit) mpz_setbit(plain->m, len-1-i);
    }
    return plain;
}


void gm_mul( gm_pubkey_t* pub,
        gm_ciphertext_t* res,
        gm_ciphertext_t* ct0,
        gm_ciphertext_t* ct1 )
{
    mpz_init(res->c);
    mpz_mul(res->c, ct0->c, ct1->c);
    mpz_mod(res->c, res->c, pub->n);
}

gm_plaintext_t* gm_plaintext_from_ui( unsigned long int x )
{
    gm_plaintext_t* pt;

    pt = (gm_plaintext_t*) malloc(sizeof(gm_plaintext_t));
    mpz_init_set_ui(pt->m, x);

    return pt;
}

gm_plaintext_t* gm_plaintext_from_bytes( void* m, int len )
{
    gm_plaintext_t* pt;

    pt = (gm_plaintext_t*) malloc(sizeof(gm_plaintext_t));
    mpz_init(pt->m);
    mpz_import(pt->m, len, 1, 1, 0, 0, m);

    return pt;
}

void* gm_plaintext_to_bytes( int len,
                             gm_plaintext_t* pt )
{
    void* buf0;
    void* buf1;
    size_t written;

    buf0 = mpz_export(0, &written, 1, 1, 0, 0, pt->m);

    if( written == len )
        return buf0;

    buf1 = malloc(len);
    memset(buf1, 0, len);

    if( written == 0 )
        /* no need to copy anything, pt->m = 0 and buf0 was not allocated */
        return buf1;
    else if( written < len )
        /* pad with leading zeros */
        memcpy(buf1 + (len - written), buf0, written);
    else
        /* truncate leading garbage */
        memcpy(buf1, buf0 + (written - len), len);

    free(buf0);

    return buf1;
}


gm_plaintext_t* gm_plaintext_from_str( char* str )
{
    return gm_plaintext_from_bytes(str, strlen(str));
}

char* gm_plaintext_to_str( gm_plaintext_t* pt )
{
    char* buf;
    size_t len;

    buf = (char*) mpz_export(0, &len, 1, 1, 0, 0, pt->m);
    buf = (char*) realloc(buf, len + 1);
    buf[len] = 0;

    return buf;
}

gm_ciphertext_t* gm_ciphertext_from_bytes( void* c, int len )
{
    gm_ciphertext_t* ct;

    ct = (gm_ciphertext_t*) malloc(sizeof(gm_ciphertext_t));
    mpz_init(ct->c);
    mpz_import(ct->c, len, 1, 1, 0, 0, c);

    return ct;
}

void* gm_ciphertext_to_bytes( int len, gm_ciphertext_t* ct )
{
    void* buf;
    int cur_len;

    cur_len = mpz_sizeinbase(ct->c, 2);
    cur_len = gm_BITS_TO_BYTES(cur_len);
    buf = malloc(len);
    memset(buf, 0, len);
    mpz_export(buf + (len - cur_len), 0, 1, 1, 0, 0, ct->c);

    return buf;
}

char* gm_pubkey_to_hex( gm_pubkey_t* pub )
{
    static char pubkey[4096];
    sprintf(pubkey, "%s\n%s",mpz_get_str(0, 16, pub->n), mpz_get_str(0, 16, pub->x));
    return pubkey;
}

char* gm_prvkey_to_hex( gm_prvkey_t* prv )
{
    static char prvkey[8192];
    sprintf(prvkey, "%s\n%s",mpz_get_str(0, 16, prv->p), mpz_get_str(0, 16, prv->q));
    return prvkey;
}


gm_pubkey_t* gm_pubkey_from_hex( char* nstr , char* xstr )
{
    gm_pubkey_t* pub;

    pub = (gm_pubkey_t*) malloc(sizeof(gm_pubkey_t));
    mpz_init_set_str(pub->n, nstr, 16);
    pub->bits = mpz_sizeinbase(pub->n, 2);
    mpz_init_set_str(pub->x, xstr, 16);
    return pub;
}

gm_prvkey_t* gm_prvkey_from_hex( char* pstr, char * qstr )
{
    gm_prvkey_t* prv;

    prv = (gm_prvkey_t*) malloc(sizeof(gm_prvkey_t));
    mpz_init_set_str(prv->p, pstr, 16);
    mpz_init_set_str(prv->q, qstr, 16);
    mpz_t pminusoneby2, qminusoneby2;
    mpz_init(pminusoneby2);
    mpz_init(qminusoneby2);
    mpz_sub_ui(pminusoneby2, prv->p, 1);
    mpz_sub_ui(qminusoneby2, prv->q, 1);
    mpz_div_ui(pminusoneby2, pminusoneby2, 2);
    mpz_div_ui(qminusoneby2, qminusoneby2, 2);
    mpz_init_set(prv->pminusoneby2, pminusoneby2);
    mpz_init_set(prv->qminusoneby2, qminusoneby2);
    mpz_clear(pminusoneby2);
    mpz_clear(qminusoneby2);
    return prv;
}

void gm_freepubkey( gm_pubkey_t* pub )
{
    mpz_clear(pub->n);
    mpz_clear(pub->x);
    free(pub);
}

void gm_freeprvkey( gm_prvkey_t* prv )
{
    mpz_clear(prv->p);
    mpz_clear(prv->q);
    free(prv);
}


void gm_freeplaintext( gm_plaintext_t* pt )
{
    mpz_clear(pt->m);
    free(pt);
}

void gm_freeciphertext( gm_ciphertext_t* ct )
{
    mpz_clear(ct->c);
    free(ct);
}

void gm_get_rand_file( void* buf, int len, char* file )
{
    FILE* fp;
    void* p;

    fp = fopen(file, "r");

    p = buf;
    while( len )
    {
        size_t s;
        s = fread(p, 1, len, fp);
        p += s;
        len -= s;
    }

    fclose(fp);
}

char* gm_ciphertext_to_hex( gm_ciphertext_t* ct )
{
    return mpz_get_str(0, 16, ct-> c);
}

gm_ciphertext_t* gm_ciphertext_from_hex( char* str )
{
    gm_ciphertext_t* ct;
    ct = (gm_ciphertext_t*) malloc(sizeof(gm_ciphertext_t));
    mpz_init_set_str(ct->c, str, 16);
    return ct;
}


void gm_get_rand_devrandom( void* buf, int len )
{
    gm_get_rand_file(buf, len, "/dev/random");
}

void gm_get_rand_devurandom( void* buf, int len )
{
    gm_get_rand_file(buf, len, "/dev/urandom");
}


