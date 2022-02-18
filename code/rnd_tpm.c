#include "rnd_tpm.h"
#include "tpm_api.h"

static int mbedtls_rnd_tpm_entropy_f_source( void *data, unsigned char *output,
                                     size_t len, size_t *olen )
{
    size_t length = len;
    
    if ( len > 65535 )
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

    if ( tpmapi_wrapped_getRandom(output, &length) )
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
    
    if ( length != len )
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

    *olen = length;
 
    return( 0 );
}

int mbedtls_rnd_tpm_init( mbedtls_ctr_drbg_context *drbg,
                          mbedtls_entropy_context *entropy )
{
    int rc = 0;

    mbedtls_ctr_drbg_init( drbg );
    mbedtls_entropy_init( entropy );

    if ( ( rc = mbedtls_entropy_add_source( entropy,
                                          mbedtls_rnd_tpm_entropy_f_source, NULL, 0,
                                          MBEDTLS_ENTROPY_SOURCE_STRONG ) ) )
        return( rc );
    
    if ( ( rc = mbedtls_ctr_drbg_seed( drbg, mbedtls_entropy_func,
                                     entropy, NULL, 0 ) ) )
        return( rc );

    return( rc );
}

int mbedtls_rnd_tpm_rand( mbedtls_ctr_drbg_context *drbg,
                          unsigned char *output, size_t output_len )
{
    return mbedtls_ctr_drbg_random( drbg, output, output_len );
} 

void mbedtls_rnd_tpm_free( mbedtls_ctr_drbg_context *drbg,
                           mbedtls_entropy_context *entropy )
{
    mbedtls_ctr_drbg_free( drbg );
    mbedtls_entropy_free( entropy );
}
