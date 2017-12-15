/*
 *         libgm - A library implementing the Goldwasser–Micali cryptosystem.
 *
 *         Copyright (C) 2012 Praveen Kumar (areteix@gmail.com)
 *
 *         This program is free software: you can redistribute it and/or modify
 *         it under the terms of the GNU General Public License as published by
 *         the Free Software Foundation, either version 3 of the License, or
 *         (at your option) any later version.
 *                                                             
 *         This program is distributed in the hope that it will be useful,
 *         but WITHOUT ANY WARRANTY; without even the implied warranty of
 *         MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *         GNU General Public License for more details.
 *                                                                               
 *         You should have received a copy of the GNU General Public License
 *         along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
        Include gmp.h before including this file.
*/

/*******
  TYPES
*******/

/*
 * This represents a gm public key, which contains the non-residue x and
 * the modulus n.
 */
typedef struct
{
    int bits;
    mpz_t x;  /* non-residue x */ 
    mpz_t n;  /* public modulus n = p q */
} gm_pubkey_t;

/*
 *      This represents a gm private key (p, q); p and q are two distinct 
 *      large primes and n = p*q. The other values are kept for efficiency 
 *      and should be considered private.
 */
typedef struct
{
    mpz_t p;   /* first large prime */ 
    mpz_t q;   /* second large prime */ 

    mpz_t pminusoneby2;  /* cached value */
    mpz_t qminusoneby2;  /* cached value */
} gm_prvkey_t;


/*
 *      This is a (semantic rather than structural) type for plaintexts.
 *      These can be converted to and from ASCII strings and byte arrays.
 */
typedef struct
{
    mpz_t m;
} gm_plaintext_t;

/*
 *      This is a (semantic rather than structural) type for ciphertexts.
 *      These can also be converted to or from byte arrays (for example in
 *      order to store them in a file).
 */
typedef struct
{
    mpz_t c;
} gm_ciphertext_t;

/*
 *       This is the type of the callback functions used to obtain the
 *       randomness needed by the probabilistic algorithms. The functions
 *       gm_get_rand_devrandom and gm_get_rand_devurandom  (documented 
 *       later) may be passed to any library function requiring 
 *       gm_get_rand_t.
 */
typedef void (*gm_get_rand_t) ( void* buf, int len );

/*****************
 BASIC OPERATIONS
*****************/

/*
 *      Generate a keypair of length modulusbits using randomness from the
 *      provided get_rand function. Space will be allocated for each of the
 *      keys, and the given pointers will be set to point to the new
 *      gm_pubkey_t and gm_prvkey_t structures. The functions
 *      gm_get_rand_devrandom and gm_get_rand_devurandom may be
 *      passed as the final argument.
 */
void gm_keygen( int modulusbits,
                      gm_pubkey_t** pub,
                      gm_prvkey_t** prv,
                      gm_get_rand_t get_rand );

/*
 *      Encrypt the given plaintext(bit) with the given public key using
 *      randomness from get_rand for blinding. If res is not null, its
 *      contents will be overwritten with the result. Otherwise, a new
 *      gm_ciphertext_t will be allocated and returned.
 */
gm_ciphertext_t* gm_enc_bit( gm_ciphertext_t* res,
                                     gm_pubkey_t* pub,
                                     int bit,
                                     gm_get_rand_t get_rand );


/*
 *      Encrypt the given plaintext and return an array of ciphertexts
 *      corresponding to each bit in the plaintext.
 */
gm_ciphertext_t** gm_enc(gm_plaintext_t* input, int* len, gm_pubkey_t* pub);


/*
 *      Decrypt the given ciphertext with the given key pair.
 *      Return 0/1 as the plaintext bit.
 */
int gm_dec_bit(gm_prvkey_t* prv, gm_ciphertext_t* ct );

/*
 *      Decrypt the array of ciphertext to get the bits and reconstruct
 *      the plaintext.
 */
gm_plaintext_t* gm_dec(gm_ciphertext_t** cipher, int len, gm_prvkey_t* prv);

/***********************************************
 HOMOMORPHISM c0 * c1 (mod n) = enc (m0 xor m1)
***********************************************/

/*
 *      Multiply the two ciphertexts assuming the modulus in the given
 *      public key and store the result in the contents of res, which is
 *      assumed to have already been allocated.
 */
void gm_mul( gm_pubkey_t* pub,
             gm_ciphertext_t* res,
             gm_ciphertext_t* ct0,
             gm_ciphertext_t* ct1 );



/*****************************
PLAINTEXT IMPORT AND EXPORT
*****************************/

/*
 *       Allocate and initialize a gm_plaintext_t from  an unsigned long 
 *       int, a null terminated string, or an array of bytes. Memory is 
 *       allocated for gm_plaintext_t here and should be freed by the caller.
 */
gm_plaintext_t* gm_plaintext_from_ui(unsigned long int x);
gm_plaintext_t* gm_plaintext_from_str( char*    str);
gm_plaintext_t* gm_plaintext_from_bytes(void* m, int len);


/*
 *      Export a gm_plaintext_t as an array of bytes or a null 
 *      terminated string. Memory is allocated for the result and it should
 *      be freed by the caller.
 */
void* gm_plaintext_to_bytes( int len,   gm_plaintext_t* pt );
char* gm_plaintext_to_str( gm_plaintext_t* pt);


/*****************************
 CIPHERTEXT IMPORT AND EXPORT
*****************************/

/*
 *      Import or export a gm_ciphertext_t from or to an array of
 *      bytes. These behave like the corresponding functions for
 *      gm_plaintext_t's.
 */
gm_ciphertext_t* gm_ciphertext_from_bytes( void* c, int len );
void* gm_ciphertext_to_bytes( int len, gm_ciphertext_t* ct );

char* gm_ciphertext_to_hex( gm_ciphertext_t* ct );
gm_ciphertext_t* gm_ciphertext_from_hex( char* str);


/**********************
 KEY IMPORT AND EXPORT
**********************/

/*
 *      Import or export public and private keys from or to hexadecimal,
 *      ASCII strings, which are suitable for I/O. In all cases, the 
 *      returned value is allocated for the caller and the values passed
 *      are unchanged.
 */
char* gm_pubkey_to_hex( gm_pubkey_t* pub );
char* gm_prvkey_to_hex( gm_prvkey_t* prv );
gm_pubkey_t* gm_pubkey_from_hex( char* nstr , char * xstr);
gm_prvkey_t* gm_prvkey_from_hex( char* pstr, char* qstr );

/********
 CLEANUP
********/

/*
 *      These free the structures allocated and returned by various
 *      functions within library and should be used when the structures are
 *      no longer needed.
 */
void gm_freepubkey( gm_pubkey_t* pub );
void gm_freeprvkey( gm_prvkey_t* prv );
void gm_freeplaintext( gm_plaintext_t* pt );
void gm_freeciphertext( gm_ciphertext_t* ct );

/***********
 MISC STUFF
***********/

#define gm_BITS_TO_BYTES(n) ((n) % 8 ? (n) / 8 + 1 : (n) / 8)

/*
 *      These functions may be passed to the gm_keygen and gm_enc 
 *      functions to provide a source of random numbers.
 */

/*
 *       gm_get_rand_devrandom reads bytes from /dev/random. On Linux, this 
 *       device will only return random bytes within the estimated number of
 *       bits of noise in the entropy pool. /dev/random should be suitable 
 *       for uses that need very high quality randomness. When the entropy
 *       pool is empty, reads from /dev/random will block until additional
 *       environmental noise is gathered. 
 */
void gm_get_rand_devrandom(  void* buf, int len );

/*
 *      gm_get_rand_random reads bytes from /dev/urandom. On Linux, this 
 *      reuses the internal pool to produce more pseudo-random bits. This 
 *      means that the call will not block, but the output may contain less 
 *      entropy than the corresponding read from /dev/random. While it is still
 *      intended as a pseudorandom number generator suitable for most 
 *      cryptographic purposes, it is not recommended for the generation of 
 *      long-term cryptographic keys.
 *
 */
void gm_get_rand_devurandom( void* buf, int len );
