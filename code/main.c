#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tpm/tpm_api.h"
#include "mbedtls/error.h"
#include "pk_tpm_rsa.h"
#include "rnd_tpm.h"

typedef struct random_context {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
} random_context;

int random_provider( void *rng_state,
                     unsigned char *output,
                     size_t len )
{
    random_context *ctx = (random_context *) rng_state;

    return mbedtls_rnd_tpm_rand( &ctx->drbg, output, len );
}

int rsa()
{
    random_context random_ctx;
    mbedtls_pk_context ctx;
    unsigned char message[32], cipher[256], decipher[256], hash[32], sig[256];
    char err[500];
    size_t sig_len = 0, cipher_len = 0, decipher_len = 0;
    int rc = 0;

    memset( message, 0x55, sizeof( message ) );
    memset( hash, 0x2a, sizeof( hash ) );
    memset( sig, 0, sizeof( sig ) );
    memset( cipher, 0, sizeof( cipher ) );
    memset( decipher, 0, sizeof( decipher ) );

    if ( tpmapi_wrapped_perso() )
    {
        printf( "main() tpmapi_wrapped_perso error\n" );
        return( 1 );
    }

    mbedtls_rnd_tpm_init( &random_ctx.drbg, &random_ctx.entropy );
    mbedtls_pk_init( &ctx );

    if ( ( rc = mbedtls_pk_setup( &ctx, &tpm_rsa_info ) ) )
    {
        mbedtls_strerror( rc, err, sizeof( err ) );
        printf( "main() mbedtls_pk_setup error: %s\n", err );
        return( 1 );
    }

    /* initialize the public component */
    //if ( ( rc = pk_tpm_rsa_init( &ctx , MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE ) ) )
    if ( ( rc = pk_tpm_rsa_init( &ctx , MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256 ) ) )
    {
        mbedtls_strerror( rc, err, sizeof( err ) );
        printf( "main() pk_tpm_rsa_init error: %s\n", err );
        return( 1 );
    }

    if ( ( rc = mbedtls_pk_check_pair( &ctx, &ctx ) ) )
    {
        mbedtls_strerror( rc, err, sizeof( err ) );
        printf( "main() mbedtls_pk_check_pair error: %s\n", err );
        return( 1 );
    }

    if ( ( rc = mbedtls_pk_sign( &ctx, MBEDTLS_MD_SHA256, hash,
                     sizeof( hash ), sig, &sig_len, NULL, NULL ) ) )
    {
        mbedtls_strerror( rc, err, sizeof( err ) );
        printf( "main() mbedtls_pk_sign error: %s\n", err );
        return( 1 );
    }

    if ( ( rc = mbedtls_pk_verify( &ctx, MBEDTLS_MD_SHA256, hash,
                     sizeof( hash ), sig, sig_len ) ) )
    {
        mbedtls_strerror( rc, err, sizeof( err ) );
        printf( "main() mbedtls_pk_verify error: %s\n", err );
        return( 1 );
    }

    if ( ( rc = mbedtls_pk_encrypt( &ctx, message, sizeof( message ),
                                  cipher, &cipher_len, sizeof( cipher ),
                                  random_provider, &random_ctx ) ) )
    {
        mbedtls_strerror( rc, err, sizeof( err ) );
        printf( "main() mbedtls_pk_encrypt error: %s\n", err );
        return( 1 );
    }

    if ( ( rc = mbedtls_pk_decrypt( &ctx, cipher, cipher_len,
                                  decipher, &decipher_len, sizeof( decipher ),
                                  NULL, NULL ) ) )
    {
        mbedtls_strerror( rc, err, sizeof( err ) );
        printf( "main() mbedtls_pk_decrypt error: %s\n", err );
        return( 1 );
    }

    if ( memcmp( message, decipher, decipher_len ) )
    {
        printf( "main() decrypted text is not equal to plain text\n" );
        return( 1 );
    }

    mbedtls_pk_free( &ctx );
    mbedtls_rnd_tpm_free( &random_ctx.drbg, &random_ctx.entropy );

    return 0;
}

int main (int argc, char *argv[])
{
    (void) argc;
    (void) argv;
#if 0
    tpmapi_unit_test();
#else
    if ( rsa() )
        exit( 1 );
#endif
    return 0;
}
