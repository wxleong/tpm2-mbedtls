#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tpm/tpm_api.h"
#include "mbedtls/error.h"
#include "pk_tpm.h"

int main (int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    mbedtls_pk_context ctx;
    unsigned char hash[32], sig[64], err[500];
    size_t sig_len = 0;
    int rc = 0;

    memset( hash, 0x2a, sizeof( hash ) );
    memset( sig, 0, sizeof( sig ));

/*
    if ( tpm_wrap_clear() ) {
        printf( "main() tpm_wrap_clear error\n" );
        exit( 1 );
    }

    if ( tpm_wrap_perso() ) {
        printf( "main() tpm_wrap_perso error\n" );
        exit( 1 );
    }
*/

    mbedtls_pk_init( &ctx );

    if ( rc = mbedtls_pk_setup( &ctx, &tpm_rsa_info ) ) {
        mbedtls_strerror( rc, err, sizeof( err ) );
        printf( "main() mbedtls_pk_setup error: %s\n", err );
        exit( 1 );
    }

    if ( rc = mbedtls_pk_sign( &ctx, MBEDTLS_MD_SHA256, hash,
                     sizeof( hash ), sig, &sig_len, NULL, NULL ) ) {
        mbedtls_strerror( rc, err, sizeof( err ) );
        printf( "main() mbedtls_pk_sign error: %s\n", err );
        exit( 1 );
    }

    if ( rc = mbedtls_pk_verify( &ctx, MBEDTLS_MD_SHA256, hash,
                     sizeof( hash ), sig, sig_len ) ) {
        mbedtls_strerror( rc, err, sizeof( err ) );
        printf( "main() mbedtls_pk_verify error: %s\n", err );
        exit( 1 );
    }

    mbedtls_pk_free( &ctx );

    return 0;
}
