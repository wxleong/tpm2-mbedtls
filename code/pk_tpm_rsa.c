#include "pk_tpm.h"
#include "tpm_api.h"

static size_t tpm_rsa_get_bitlen( const void *ctx )
{
    mbedtls_tpm_rsa* self = (mbedtls_tpm_rsa*) ctx;
    return( 8 * mbedtls_rsa_get_len( &self->rsa ) );
}

static int tpm_rsa_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_RSA );
}

static int tpm_rsa_verify( void *ctx, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len )
{
    mbedtls_tpm_rsa* self = (mbedtls_tpm_rsa*) ctx;
    size_t rsa_len = mbedtls_rsa_get_len( &self->rsa );
    int ret = 0;

    if( md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    /* library limitation */
    if(md_alg != MBEDTLS_MD_SHA256)
        return( MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE );

    if( sig_len < rsa_len )
        return( MBEDTLS_ERR_RSA_VERIFY_FAILED );

    if( hash_len == 0 )
    {
        const mbedtls_md_info_t *md_info;

        md_info = mbedtls_md_info_from_type( md_alg );
        if( md_info == NULL )
            return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

        hash_len = mbedtls_md_get_size( md_info );
    }

    if( ret = mbedtls_rsa_pkcs1_verify( &self->rsa, NULL, NULL,
                                        MBEDTLS_RSA_PUBLIC, md_alg,
                                        (unsigned int) hash_len, hash, sig ) )
        return( ret );


    if( sig_len > rsa_len )
        return( MBEDTLS_ERR_PK_SIG_LEN_MISMATCH );

    return( 0 );
}

static int tpm_rsa_sign( void *ctx, mbedtls_md_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng )
{
    (void) f_rng;
    (void) p_rng;
    mbedtls_tpm_rsa* self = (mbedtls_tpm_rsa*) ctx;

    if( md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    /* library limitation */
    if(md_alg != MBEDTLS_MD_SHA256)
        return( MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE );

    if( hash_len == 0 )
    {
        const mbedtls_md_info_t *md_info;

        md_info = mbedtls_md_info_from_type( md_alg );
        if( md_info == NULL )
            return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

        hash_len = mbedtls_md_get_size( md_info );
    }

    *sig_len = mbedtls_rsa_get_len( &self->rsa );

    if ( tpm_wrapped_sign(hash, hash_len, sig, sig_len) )
        return( MBEDTLS_ERR_RSA_PRIVATE_FAILED );

    return( 0 );
}

static int tpm_rsa_decrypt( void *ctx,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    return( 0 );
}

static int tpm_rsa_encrypt( void *ctx,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedtls_tpm_rsa* self = (mbedtls_tpm_rsa*) ctx;
    *olen = mbedtls_rsa_get_len( &self->rsa );

    if( *olen > osize )
        return( MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE );

    return( mbedtls_rsa_pkcs1_encrypt( &self->rsa, f_rng, p_rng, MBEDTLS_RSA_PUBLIC,
                                       ilen, input, output ) );
}

static int tpm_rsa_check_pair( const void *pub, const void *prv )
{
    unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
    unsigned char hash[32] = {0};
    size_t sig_len = 0;
    int ret;

    if( ( ret = tpm_rsa_sign( (void *) prv, MBEDTLS_MD_SHA256,
                              hash, sizeof( hash ),
                              sig, &sig_len, NULL, NULL ) ) != 0 )
        return( ret );

    if(mbedtls_rsa_pkcs1_verify( (mbedtls_rsa_context *) pub, NULL, NULL,
                                 MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256,
                                 (unsigned int) sizeof( hash ), hash, sig ) != 0 )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

    return 0;
}

static void tpm_rsa_free( void *ctx )
{
    if(ctx != NULL)
    {
        mbedtls_tpm_rsa* self = (mbedtls_tpm_rsa*) ctx;
        mbedtls_rsa_free( &self->rsa );
        mbedtls_free( ctx );
        /*if ( tpm_wrapped_clear() ) {
            printf( "tpm_wrapped_clear error\n" );
        }*/
   }
}

static void *tpm_rsa_alloc( void )
{
    if ( tpm_wrapped_perso() ) {
        printf( "tpm_wrapped_perso error\n" );
        return NULL;
    }

    mbedtls_tpm_rsa *ctx = mbedtls_calloc( 1, sizeof( mbedtls_tpm_rsa ) );

    if ( ctx != NULL ) {
        int exponent;
        unsigned char mod[256];
        size_t modlen = sizeof(mod);
        const unsigned char exp[] = {0x1,0x0,0x1}; // exponent 65537
        mbedtls_rsa_context *rsa = &ctx->rsa;

        mbedtls_rsa_init( rsa, 0, 0 );

        if ( tpm_wrapped_getRsaPk( &exponent, mod, &modlen ) )
        {
            printf( "tpm_wrapped_getRsaPk error\n" );
            goto error;
        }

        // set RSA signature schemes to RSASSA-PKCS1-v1_5
        mbedtls_rsa_init( rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE );
        rsa->ver = 0;

        if ( mbedtls_mpi_read_binary( &rsa->N, mod, modlen ) )
            goto error;

        if ( exponent != 65537 )
            goto error;

        if ( mbedtls_mpi_read_binary( &rsa->E, exp, 3 ) )
            goto error;

        rsa->len = mbedtls_mpi_bitlen( &rsa->N ) / 8;

        if ( mbedtls_rsa_check_pubkey( rsa ) )
            goto error;
    }

    return( ctx );
error:
    tpm_rsa_free( ctx );
    return NULL;
}

static void tpm_rsa_debug( const void *ctx, mbedtls_pk_debug_item *items )
{
    (void) ctx;
    (void) items;
}

const mbedtls_pk_info_t tpm_rsa_info =
{
    MBEDTLS_PK_RSA,
    TPM_NAME,
    tpm_rsa_get_bitlen,
    tpm_rsa_can_do,
    tpm_rsa_verify,
    tpm_rsa_sign,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    tpm_rsa_decrypt,
    tpm_rsa_encrypt,
    tpm_rsa_check_pair,
    tpm_rsa_alloc,
    tpm_rsa_free,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    tpm_rsa_debug
};
