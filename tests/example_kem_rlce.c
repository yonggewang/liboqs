/*
 * example_kem_rlce.c
 *
 * Minimal example of a Diffie-Hellman-style post-quantum key encapsulation
 * implemented in liboqs.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

/* Cleaning up memory etc */
void cleanup_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len);

void cleanup_heap(uint8_t *secret_key, uint8_t *shared_secret_e,
                  uint8_t *shared_secret_d, uint8_t *public_key,
                  uint8_t *ciphertext, OQS_KEM *kem);

static OQS_STATUS example_stack(void) {
#ifndef OQS_ENABLE_KEM_rlce_l1 // if RLCE was not enabled at compile-time
	printf("[example_stack] OQS_ENABLE_KEM_rlce_l1 was not enabled at "
	       "compile-time.\n");
	return OQS_ERROR;
#else
	uint8_t public_key[RLCE_L1_pub_key_size];
	uint8_t secret_key[RLCE_L1_sec_size];
	uint8_t ciphertext[RLCE_L1_cipherLen];
	uint8_t shared_secret_e[OQS_KEM_RLCE_ss_len];
	uint8_t shared_secret_d[OQS_KEM_RLCE_ss_len];

	OQS_STATUS rc = crypto_kem_keygenerate1(public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: crypto_kem_keygenerate1 failed!\n");
		cleanup_stack(secret_key, RLCE_L1_sec_size,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_RLCE_ss_len);

		return OQS_ERROR;
	}
	rc = crypto_kem_encapsulate1(ciphertext, shared_secret_e, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: crypto_kem_encapsulate1 failed!\n");
		cleanup_stack(secret_key, RLCE_L1_sec_size,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_RLCE_ss_len);

		return OQS_ERROR;
	}
	rc = crypto_kem_decapsulate1(shared_secret_d, ciphertext, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: crypto_kem_decapsulate1 failed!\n");
		cleanup_stack(secret_key, RLCE_L1_sec_size,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_RLCE_ss_len);

		return OQS_ERROR;
	}
	printf("[example_stack] OQS_ENABLE_KEM_rlce_l1 operations completed.\n");

	return OQS_SUCCESS; // success!
#endif
}

static OQS_STATUS example_heap(void) {
	OQS_KEM *kem = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *ciphertext = NULL;
	uint8_t *shared_secret_e = NULL;
	uint8_t *shared_secret_d = NULL;

	kem = OQS_KEM_new(OQS_KEM_alg_RLCE_l1);
	if (kem == NULL) {
		printf("[example_heap]  OQS_ENABLE_KEM_rlce_l1 was not enabled at "
		       "compile-time.\n");
		return OQS_ERROR;
	}

	public_key = malloc(kem->length_public_key);
	secret_key = malloc(kem->length_secret_key);
	ciphertext = malloc(kem->length_ciphertext);
	shared_secret_e = malloc(kem->length_shared_secret);
	shared_secret_d = malloc(kem->length_shared_secret);
	if ((public_key == NULL) || (secret_key == NULL) || (ciphertext == NULL) ||
	        (shared_secret_e == NULL) || (shared_secret_d == NULL)) {
		fprintf(stderr, "ERROR: malloc failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}

	OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_keypair failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}
	rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_encaps failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}
	rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_decaps failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem);

		return OQS_ERROR;
	}

	printf("[example_heap]  OQS_ENABLE_KEM_rlce_l1 operations completed.\n");
	cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
	             ciphertext, kem);

	return OQS_SUCCESS; // success
}

int main(void) {
	if (example_stack() == OQS_SUCCESS && example_heap() == OQS_SUCCESS) {
		return EXIT_SUCCESS;
	} else {
		return EXIT_FAILURE;
	}
}

void cleanup_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
	OQS_MEM_cleanse(shared_secret_e, shared_secret_len);
	OQS_MEM_cleanse(shared_secret_d, shared_secret_len);
}

void cleanup_heap(uint8_t *secret_key, uint8_t *shared_secret_e,
                  uint8_t *shared_secret_d, uint8_t *public_key,
                  uint8_t *ciphertext, OQS_KEM *kem) {
	if (kem != NULL) {
		OQS_MEM_secure_free(secret_key, kem->length_secret_key);
		OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
		OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(ciphertext);
	OQS_KEM_free(kem);
}
