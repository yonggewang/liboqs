/* reedsolomon.c
 * Yongge Wang 
 *
 * Code was written: November 3, 2016-
 *
 * reedsolomon.c implements Reed-Solomon encoding/decoding  
 * operations for RLCE scheme that is part of the package 
 * RLCE.tar - Random Linear Code Encryption Scheme
 *
 * Copyright (C) 2016 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 */

#include "rlce.h"

void get_syndrome(poly_t code, poly_t syndrome, int m);
int berlekamp_massey(poly_t syndrome, poly_t C, int m);

poly_t initialize_RS (int codelen, int codedim, int m) {
  int result=GF_init_logexp_table(m);
  if (result <0)  return NULL;
  poly_t generatorPoly;
  generatorPoly=poly_init(codelen);  
  getGenPoly(codelen-codedim, generatorPoly, m);
  return generatorPoly;
}

int rs_encode (poly_t genPoly, poly_t message, poly_t code, int m) {
  int result =poly_mul(genPoly, message, code, m);  
  if (result<0) return REENCODEERROR;
  return 0;
}

void get_syndrome(poly_t code, poly_t syndrome, int m) {
  int i;
    field_t *input;
    input=calloc(1+syndrome->deg, sizeof(field_t));
    for (i=0;i<1+syndrome->deg; i++) input[i]=i+1;
    GF_evalpoly(1, code, input, syndrome->coeff, 1+syndrome->deg, m);
    free(input);
  poly_deg(syndrome);
}

int berlekamp_massey(poly_t syndrome, poly_t C, int m) {
  int x=1, L=0, b=1, N=0;
  poly_t B, T, tmpP;
  T = poly_init(syndrome->size);
  B = poly_init(syndrome->size);
  field_t *tmpB =calloc(syndrome->size, sizeof(field_t));  
  B->coeff[0]=1;
  B->deg =0;
  memset(C->coeff, 0, (C->size) *sizeof(field_t));
  C->coeff[0]=1;
  C->deg = 0;
  field_t d, tmp1;
  for (N=0; N<=syndrome->deg; N++) {
    d=GF_vecreversemul(C->coeff,&(syndrome->coeff[N-L]),L+1,m); 
    if (d != field_zero()) {
      tmp1 = GF_div(d, b,m); 
      if (N<2*L) {
	GF_mulvec(tmp1, B->coeff, tmpB,1+B->deg,  m);
	GF_addvec(tmpB,&(C->coeff[x]),NULL,1+B->deg);
	if (C->deg < x+B->deg) C->deg = x+B->deg;
      	x++;
      } else {
	memcpy(T->coeff, C->coeff, (1+C->deg)*sizeof(field_t));
	T->deg=C->deg;
	GF_mulvec(tmp1, B->coeff, NULL,1+B->deg,m);
	GF_addvec(B->coeff,&(C->coeff[x]),NULL,1+B->deg);
	if (C->deg<x+B->deg) C->deg=x+B->deg;
	L=N+1-L;
	tmpP=B;
	B=T;
	T=tmpP;
	b=d;
	x=1;
      }
    } else x++;
  }
  free(tmpB);
  poly_free(B);
  poly_free(T);
  return L;
}

int decode(poly_t omega, poly_t syndrome, poly_t lambda, int codelen, int codedim, int m) {
  int ret=berlekamp_massey(syndrome, lambda, m);
  poly_mul(lambda, syndrome, omega, m);
  memset(&(omega->coeff[codelen-codedim]),0,(1+omega->deg-codelen+codedim)*sizeof(field_t));
  poly_deg(omega);
  return ret;
}

poly_t rs_decode(poly_t code, int codelen, int codedim, field_t eLocation[], int m) {
  int numRoots;
  field_t lambdaRoots[codelen-codedim];
  memset(lambdaRoots,0, (codelen-codedim)*sizeof(field_t)); //int eLocation[n-k];
  poly_t syndrome, omega, lambda, lambdaDerivative, error, result;
  memset(eLocation, 0, (codelen-codedim)*sizeof(field_t)); 
  syndrome = poly_init(1+codelen-codedim);
  syndrome->deg=codelen-codedim-1;  
  omega = poly_init(2*(1+codelen-codedim));
  lambda =poly_init(1+codelen-codedim);
  lambdaDerivative =poly_init(1+codelen-codedim);
  get_syndrome(code, syndrome, m);
  int i,j;

  decode(omega, syndrome, lambda, codelen, codedim, m);
  error = poly_init(codelen);  
  
  lambdaDerivative->deg = lambda->deg -1;
  for (i=0; i<= (lambda->deg); i+=2) lambdaDerivative->coeff[i]=lambda->coeff[i+1];
  poly_deg(lambdaDerivative);

    numRoots= find_roots_Chien(lambda, lambdaRoots, eLocation, m);
    field_t *omegaoutput=calloc(numRoots, sizeof(field_t));
    field_t *lanmdaDoutput=calloc(numRoots, sizeof(field_t));
    GF_evalpoly(0,omega, lambdaRoots, omegaoutput, numRoots, m);
    GF_evalpoly(0,lambdaDerivative, lambdaRoots, lanmdaDoutput,numRoots,  m);
    GF_divvec(omegaoutput,lanmdaDoutput,numRoots, m);
    for (j=0;j< numRoots;j++) error->coeff[eLocation[j]] = omegaoutput[j];
    free(lanmdaDoutput);
    free(omegaoutput);
  
  poly_free(omega);
  poly_deg(error);  
  poly_free(lambdaDerivative);
  poly_free(lambda);
  result = poly_init(codelen);
  poly_add(code, error, result);
  poly_free(error);
  poly_free(syndrome);
  return result;
}


