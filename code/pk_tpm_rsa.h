#ifndef PK_TPM_H_
#define PK_TPM_H_

#include "mbedtls/platform.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/entropy.h"

#define TPM_NAME "optiga-tpm2"

typedef struct
{
    mbedtls_rsa_context rsa;
    // handle
} mbedtls_tpm_rsa;

extern const mbedtls_pk_info_t tpm_rsa_info;
extern const mbedtls_pk_info_t tpm_ecp_info;

int tpm_pk_init( mbedtls_pk_context *ctx , int padding_scheme, int hash_algo);

#endif
