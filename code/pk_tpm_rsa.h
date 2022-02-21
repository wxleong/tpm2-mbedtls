#ifndef PK_TPM_RSA_H_
#define PK_TPM_RSA_H_

#include "mbedtls/platform.h"
#include "mbedtls/pk_internal.h"

#define TPM_NAME "optiga-tpm2"

typedef struct
{
    mbedtls_rsa_context rsa;
} mbedtls_tpm_rsa;

extern const mbedtls_pk_info_t tpm_rsa_info;

int pk_tpm_rsa_init( mbedtls_pk_context *ctx , int padding_scheme, int hash_algo);

#endif
