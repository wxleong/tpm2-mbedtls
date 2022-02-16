#ifndef RND_TPM_H_
#define RND_TPM_H_

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

int mbedtls_rnd_tpm_init( mbedtls_ctr_drbg_context *drbg,
                          mbedtls_entropy_context *entropy );
int mbedtls_rnd_tpm_rand( mbedtls_ctr_drbg_context *drbg,
                          unsigned char *output, size_t output_len );
void mbedtls_rnd_tpm_free( mbedtls_ctr_drbg_context *drbg,
                           mbedtls_entropy_context *entropy );

#endif
