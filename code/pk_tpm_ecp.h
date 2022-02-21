#ifndef PK_TPM_ECP_H_
#define PK_TPM_ECP_H_

#include "mbedtls/platform.h"
#include "mbedtls/pk_internal.h"

#define TPM_NAME "optiga-tpm2"

typedef struct
{
    mbedtls_ecp_keypair ecp;
} mbedtls_tpm_ecp;

extern const mbedtls_pk_info_t tpm_ecp_info;

int pk_tpm_ecp_init( mbedtls_pk_context *ctx );

#endif
