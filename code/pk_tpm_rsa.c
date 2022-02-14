#include "pk_tpm.h"
#include "tpm_api.h"

static size_t tpm_rsa_get_bitlen( const void *ctx )
{
    mbedtls_tpm_rsa* self = (mbedtls_tpm_rsa*)ctx;
    return( 8 * mbedtls_rsa_get_len( &self->rsa ) );
}

static int tpm_rsa_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_RSA ||
            type == MBEDTLS_PK_RSASSA_PSS );
}

static int tpm_rsa_verify( void *ctx, mbedtls_md_type_t md_alg,
                                     const unsigned char *hash, size_t hash_len,
                                     const unsigned char *sig, size_t sig_len )
{
    return( 0 );
}

static int tpm_rsa_sign( void *ctx, mbedtls_md_type_t md_alg,
                                    const unsigned char *hash, size_t hash_len,
                                    unsigned char *sig, size_t *sig_len,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng )
{
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
    return( 0 );
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

static void *tpm_rsa_alloc( void )
{
    if (tpm_wrap_perso()) {
        printf("tpm_wrap_perso error\n");
        return NULL;
    }

    mbedtls_tpm_rsa *ctx = mbedtls_calloc( 1, sizeof( mbedtls_tpm_rsa ) );

    if (ctx != NULL)
        mbedtls_rsa_init(&ctx->rsa, 0, 0);

    return( ctx );
}

static void tpm_rsa_free( void *ctx )
{
    if(ctx != NULL)
    {
        mbedtls_tpm_rsa* self = (mbedtls_tpm_rsa*)ctx;
        mbedtls_rsa_free(&self->rsa);
        mbedtls_free( ctx );
        if (tpm_wrap_clear()) {
            printf("tpm_wrap_clear error\n");
        }
   }
}

static void tpm_rsa_debug( const void *ctx, mbedtls_pk_debug_item *items )
{
    items->type = MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.N";
    items->value = &( ((mbedtls_rsa_context *) ctx)->N );

    items++;

    items->type = MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.E";
    items->value = &( ((mbedtls_rsa_context *) ctx)->E );
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
