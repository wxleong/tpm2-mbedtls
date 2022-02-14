#include "mbedtls/platform.h"
#include "mbedtls/pk_internal.h"

#define TPM_NAME "optiga-tpm2"

typedef struct
{
    mbedtls_rsa_context rsa;
    // handle
} mbedtls_tpm_rsa;

const mbedtls_pk_info_t tpm_rsa_info;
const mbedtls_pk_info_t tpm_ecp_info;

