/* rlce.h
 * Copyright (C) 2016-2019 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include <oqs/oqs.h>
#include <oqs/rand.h>
#include <oqs/aes.h>
#include <oqs/sha2.h>

#ifndef _RLCEH_
#define _RLCEH_
#define PARASIZE 20       /* plese do not change!!!!!                      */

OQS_API OQS_STATUS crypto_kem_keygenerateX(int scheme, unsigned char *pk, unsigned char *sk);
OQS_API OQS_STATUS crypto_kem_encapsulateX(size_t pkLen, size_t cipherLen, unsigned char *ct,unsigned char *ss,const unsigned char *pk);
OQS_API OQS_STATUS crypto_kem_decapsulateX(size_t secLen, size_t cipherLen, unsigned char *ss,const unsigned char *ct,const unsigned char *sk);
#define OQS_KEM_RLCE_ss_len 64

#ifdef OQS_ENABLE_KEM_rlce_l1
#define RLCE_L1_pub_key_size 188001
#define RLCE_L1_sec_size 310116
#define RLCE_L1_cipherLen 988
OQS_KEM *OQS_KEM_rlce_l1_new(void);
OQS_API OQS_STATUS crypto_kem_keygenerate1(unsigned char *pk, unsigned char *sk);
OQS_API OQS_STATUS crypto_kem_encapsulate1(unsigned char *ct,unsigned char *ss,const unsigned char *pk);
OQS_API OQS_STATUS crypto_kem_decapsulate1(unsigned char *ss,const unsigned char *ct,const unsigned char *sk);
#endif

#ifdef OQS_ENABLE_KEM_rlce_l3
#define RLCE_L3_pub_key_size 450761
#define RLCE_L3_seckey_size 747393
#define RLCE_l3_cipherLen 1545
OQS_KEM *OQS_KEM_rlce_l3_new(void);
OQS_API OQS_STATUS crypto_kem_keygenerate3(unsigned char *pk, unsigned char *sk);
OQS_API OQS_STATUS crypto_kem_encapsulate3(unsigned char *ct,unsigned char *ss,const unsigned char *pk);
OQS_API OQS_STATUS crypto_kem_decapsulate3(unsigned char *ss,const unsigned char *ct,const unsigned char *sk);
#endif

#ifdef OQS_ENABLE_KEM_rlce_l5
#define RLCE_L5_pub_key_size 1232001
#define RLCE_L5_seckey_size 1773271
#define RLCE_l5_cipherLen 2640
OQS_KEM *OQS_KEM_rlce_l5_new(void);
OQS_API OQS_STATUS crypto_kem_keygenerate5(unsigned char *pk, unsigned char *sk);
OQS_API OQS_STATUS crypto_kem_encapsulate5(unsigned char *ct,unsigned char *ss,const unsigned char *pk);
OQS_API OQS_STATUS crypto_kem_decapsulate5(unsigned char *ss,const unsigned char *ct,const unsigned char *sk);
#endif

#define field_unit() 1
#define field_zero() 0
#define fieldSize(m) (1 << m)
typedef unsigned short field_t;

typedef struct vector {
  int size;
  field_t *data;
} *vector_t;

typedef struct matrix {
  int numR;
  int numC;
  field_t **data;
} *matrix_t;

typedef struct matrixA {
  int size;
  matrix_t *A;
} *matrixA_t;

typedef struct polynomial {
  int deg, size; 
  field_t * coeff;
} * poly_t;


typedef struct RLCE_private_key {
  size_t* para;
  vector_t perm1; /* inverse of perm1*/
  vector_t perm2;/* inverse of perm2*/
  poly_t generator;
  matrixA_t A;/* inverse of A*/
  matrix_t S; /* inverse of S */
  vector_t grs;/* inverse of grs */
  matrix_t G; /* public key to speed up decryption */
} * RLCE_private_key_t;


typedef struct RLCE_public_key {
  size_t* para;
  matrix_t G;
} * RLCE_public_key_t;

int pk2B(RLCE_public_key_t pk, unsigned char pkB[], size_t *blen);
int sk2B(RLCE_private_key_t sk, unsigned char skB[], size_t *blen);
RLCE_public_key_t B2pk(const unsigned char binByte[], unsigned long long blen);
RLCE_private_key_t B2sk(const unsigned char binByte[], unsigned long long blen);
void hex2char(char * pos, unsigned char hexChar[], int charlen);

poly_t initialize_RS(int codelen, int codedim, int m);
int rs_encode (poly_t genPoly, poly_t message, poly_t code, int m);
poly_t rs_decode(poly_t code, int codelen, int codedim,
		 field_t eLocation[], int m); /*eLocation[m-k]*/

RLCE_private_key_t RLCE_private_key_init (size_t para[]);
void RLCE_free_sk(RLCE_private_key_t sk);
RLCE_public_key_t RLCE_public_key_init (size_t para[]);
void RLCE_free_pk(RLCE_public_key_t pk);
int RLCE_key_setup (unsigned char entropy[], int entropylen,
		    unsigned char nonce[], int noncelen,
		    RLCE_public_key_t  pk, RLCE_private_key_t sk);

int getRLCEparameters(size_t para[], size_t scheme, size_t padding);
int RLCE_encrypt(unsigned char msg[], unsigned char entropy[], size_t entropylen,
		 unsigned char nonce[], size_t noncelen,
		 RLCE_public_key_t pk, unsigned char cipher[], unsigned long long *clen);
int RLCE_decrypt(unsigned char cipher[], unsigned long long clen, RLCE_private_key_t sk,
		 unsigned char msg[], unsigned long long *mlen);

/* GaloisField.h */

extern short *GFlogTable[17];
extern short *GFexpTable[17];
extern short **GFmulTable[17];
extern short **GFdivTable[17];
extern int fieldOrder[17];
extern int fieldSize[17];
extern int GF_init_logexp_table(int m); /* 0 on success, -1 on failure */
extern field_t GF_tablediv(field_t x, field_t y, int m);
extern int GF_init_mult_table(int m);
void GF_expvec(field_t vec[], int size, int m);
void GF_mulvec(field_t x, field_t vec[], field_t dest[],int dsize, size_t m);
void GF_vecdiv(field_t x, field_t vec[], field_t dest[],int dsize, size_t m);
void GF_mulexpvec2(field_t x, field_t vec[], field_t dest[],int dsize, size_t m);
void GF_logmulvec(int xlog, field_t vec[], field_t dest[],int dsize, size_t m);
void GF_vecinverse(field_t vec1[], field_t vec2[], int vecsize, int m);
extern int GF_addvec(field_t vec1[], field_t vec2[],field_t vec3[], size_t vecSize);
int GF_addF2vec(field_t x, field_t vec2[],field_t vec3[], size_t vecSize);
void GF_divvec(field_t vec1[],field_t vec2[], int vsize, size_t m);
int GF_vecreversemul(field_t vec1[],field_t vec2[],int vsize,int m);
void GF_evalpoly(int log, poly_t p, field_t input[], field_t output[], int size, int m);
void GF_rsgenerator2optG(matrix_t optG, poly_t generator, field_t randE[], int m);
void GF_vecvecmul(field_t v1[], field_t v2[], field_t v3[], int vsize, size_t m);
void getGenPoly (int deg, poly_t g, int m);
void rootsLocation(field_t rts[],int nRts,field_t eLoc[],field_t rtLog[],int m);
void GF_mulAinv(field_t cp[], matrixA_t A, field_t C1[], int m);
void GF_x2px(field_t vec[], field_t dest[], int size, int m);
extern field_t GF_fexp(field_t x, int y, int m);
field_t GF_mul(field_t x, field_t y, int m);

#define GF_exp(x,m) GFexpTable[m][x]
#define GF_log(x,m) GFlogTable[m][x]
#define GF_div(x, y,m) ((x) ?  GFexpTable[m][GFlogTable[m][x]+fieldOrder[m]-GFlogTable[m][y]]:0)
#define GF_tablemul(x,y,m) GFmulTable[m][x][y]
#define GF_mulx(x,y,m) ((y)?GFexpTable[m][GFlogTable[m][x]+GFlogTable[m][y]]:0)
#define GF_regmul(x,y,m) ((x)?GF_mulx(x,y,m):0)


poly_t poly_init(size_t size);
void poly_clear(poly_t p);
void poly_zero(poly_t p);
void poly_copy(poly_t p, poly_t dest);
void poly_free(poly_t p);
int poly_mul(poly_t f, poly_t g, poly_t r, int m);
int poly_mul_standard(poly_t p, poly_t q, poly_t r, int m);
int poly_mul_karatsuba(poly_t f, poly_t g, poly_t r, int m);
int poly_div(poly_t p, poly_t d, poly_t q, poly_t dest, int m);
int poly_add(poly_t p, poly_t q, poly_t dest);
int poly_deg(poly_t p);
int poly_quotient (poly_t p, poly_t d, poly_t q, int m);
int poly_gcd(poly_t p1, poly_t p2, poly_t gcd, int m);
int find_roots (poly_t lambda, field_t roots[], field_t eLocation[], int m);
int find_roots_Chien (poly_t p, field_t roots[], field_t eLocation[],int m);
int find_roots_BTA(poly_t p, field_t pRoots[], int m);

matrix_t matrix_init(int r, int c);
void matrix_free(matrix_t A);
void matrix_zero(matrix_t A);
matrix_t matrix_clone(matrix_t A);
int matrix_copy(matrix_t mat, matrix_t dest);
void matrix_print(matrix_t X);
int matrix_mul(matrix_t A, matrix_t B, matrix_t dest,int m);
int matrix_standard_mul(matrix_t A, matrix_t B, matrix_t C, int m);
int matrix_vec_mat_mul(field_t V[], int vsize, matrix_t B, field_t dest[],int dsize, int m);
int vector_copy(vector_t v, vector_t dest);
void vector_print(vector_t v);
matrixA_t matrixA_init(int size);
void matrixA_free(matrixA_t A);
int matrix_col_permutation(matrix_t A, vector_t per);
int matrix_row_permutation(vector_t per, matrix_t A);
matrix_t matrix_mul_A(matrix_t U, matrixA_t A, int start, int m);
int matrix_opt_mul_A(matrix_t G, matrixA_t A, int startP, int m);
int matrix_echelon(matrix_t G, int m);
matrix_t matrix_join(matrix_t G, matrix_t R);
int matrixA_copy(matrixA_t mat, matrixA_t dest);
int RLCE_MGF512(unsigned char mgfseed[], int mgfseedLen,
		unsigned char mask[], int maskLen);

vector_t vec_init(int n);
void vector_free(vector_t v);
vector_t permu_inv(vector_t p);
int getRandomMatrix(matrix_t mat, field_t randE[]);
vector_t getPermutation(int size, int t, unsigned char randBytes[]);
int randomBytes2FE(unsigned char randomBytes[], int nRB,
		   field_t output[], int outputSize, int m);
int getShortIntegers(unsigned char randomBytes[],
		     unsigned short output[], int outputSize);
int getMatrixAandAinv(matrixA_t mat, matrixA_t matInv,
			    field_t randomElements[], int randElen,int m);

void I2BS (size_t X, unsigned char S[], int slen);
int BS2I (unsigned char S[], int slen);
int B2FE9 (unsigned char bytes[], size_t BLen, vector_t FE);
int FE2B9 (vector_t FE, unsigned char bytes[], size_t BLen);
int B2FE10 (unsigned char bytes[], size_t BLen, vector_t FE);
int FE2B10 (vector_t FE, unsigned char bytes[], size_t BLen);
int B2FE11 (unsigned char bytes[], size_t BLen, vector_t FE);
int FE2B11 (vector_t FE, unsigned char bytes[], size_t BLen);
int B2FE12 (unsigned char bytes[], size_t BLen, vector_t FE);
int FE2B12 (vector_t FE, unsigned char bytes[], size_t BLen);
void hashTObytes(unsigned char bytes[], int bSize, unsigned int hash[]);

#endif
#define GFTABLEERR -6
#define POLYMULTERRR -8
#define MATMULAINVERROR -10
#define POLYNOTFULLDIV -11
#define NEEDNEWRANDOMSEED -12
#define MATRIXCOPYERROR -13
#define MATRIXACOPYERROR -14
#define MATRIXMULERROR -15
#define VECMATRIXMULERROR -16
#define MATRIXVECMULERROR -17
#define MATRIXCOLPERERROR -18
#define MATRIXROWPERERROR -19
#define MATRIXMULAERROR -20
#define GETPERERROR -24
#define REENCODEERROR -25
#define MATRIXRNOTFULLRANK -27
#define DEPADDINGFAIL -30
#define RLCEIDPARANOTDEFINED -32
#define B2FEORFE2BNOTDEFINED -33
#define BYTEVECTORTOOSMALL -35
#define PADPARAERR -37
#define DRBGFAIL -41
#define ECHELONFAIL -44
#define DECODING2NOTINVERTIBLE -45
#define TOOMANYERRORS -56
#define CIPHERNULL -58
#define CIPHER2SMALL -59
#define CIPHERSIZEWRONG -60
#define MSGNULL -61
#define SMG2SMALL -62
#define KEYBYTE2SMALL -53
#define SKWRONG -64
#define SKNULL -65
#define FGETSWRONG -66
