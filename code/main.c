#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tpm/tpm_api.h"
#include "mbedtls/error.h"
#include "pk_tpm.h"
#include "rnd_tpm.h"

typedef struct random_context {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
} random_context;

int tpm_rnd( void *rng_state,
             unsigned char *output,
             size_t len )
{
    random_context *ctx = (random_context *) rng_state;
    return mbedtls_rnd_tpm_rand( &ctx->drbg, output, len );
}

int main (int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    random_context rnd_ctx;
    mbedtls_pk_context ctx;
    unsigned char message[32], out[256], hash[32], sig[64], err[500];
    size_t sig_len = 0, out_len = 0;
    int rc = 0;

    memset( message, 0x55, sizeof( message ) );
    memset( hash, 0x2a, sizeof( hash ) );
    memset( sig, 0, sizeof( sig ));

/*
    if ( tpm_wrapped_clear() )
    {
        printf( "main() tpm_wrapped_clear error\n" );
        exit( 1 );
    }

    if ( tpm_wrapped_perso() )
    {
        printf( "main() tpm_wrapped_perso error\n" );
        exit( 1 );
    }
*/

    mbedtls_rnd_tpm_init( &rnd_ctx.drbg, &rnd_ctx.entropy );
    mbedtls_pk_init( &ctx );

    if ( rc = mbedtls_pk_setup( &ctx, &tpm_rsa_info ) )
    {
        mbedtls_strerror( rc, err, sizeof( err ) );
        printf( "main() mbedtls_pk_setup error: %s\n", err );
        exit( 1 );
    }

    if ( rc = mbedtls_pk_check_pair( &ctx, &ctx ) )
    {
        mbedtls_strerror( rc, err, sizeof( err ) );
        printf( "main() mbedtls_pk_check_pair error: %s\n", err );
        exit( 1 );
    }

    if ( rc = mbedtls_pk_sign( &ctx, MBEDTLS_MD_SHA256, hash,
                     sizeof( hash ), sig, &sig_len, NULL, NULL ) )
    {
        mbedtls_strerror( rc, err, sizeof( err ) );
        printf( "main() mbedtls_pk_sign error: %s\n", err );
        exit( 1 );
    }

    if ( rc = mbedtls_pk_verify( &ctx, MBEDTLS_MD_SHA256, hash,
                     sizeof( hash ), sig, sig_len ) )
    {
        mbedtls_strerror( rc, err, sizeof( err ) );
        printf( "main() mbedtls_pk_verify error: %s\n", err );
        exit( 1 );
    }

    if ( rc = mbedtls_pk_encrypt( &ctx, message, sizeof( message ),
                                  out, &out_len, sizeof( out ),
                                  tpm_rnd, &rnd_ctx ) )
    {
        mbedtls_strerror( rc, err, sizeof( err ) );
        printf( "main() mbedtls_pk_encrypt error: %s\n", err );
        exit( 1 );
    }

    mbedtls_pk_free( &ctx );
    mbedtls_rnd_tpm_free( &rnd_ctx.drbg, &rnd_ctx.entropy );

    return 0;
}
