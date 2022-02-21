#include <string.h> 
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/error.h"
#include "pk_tpm_ecp.h"
#include "tpm_api.h"

static int ecdsa_signature_to_asn1( const mbedtls_mpi *r, const mbedtls_mpi *s,
                                    unsigned char *sig, size_t *slen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN] = {0};
    unsigned char *p = buf + sizeof( buf );
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &p, buf, s ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &p, buf, r ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &p, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &p, buf,
                                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

    memcpy( sig, p, len );
    *slen = len;

    return( 0 );
}

static size_t tpm_ecp_get_bitlen( const void *ctx )
{
    mbedtls_tpm_ecp* self = (mbedtls_tpm_ecp*)ctx;
    return( self->ecp.grp.pbits );
}

static int tpm_ecp_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_ECKEY    ||
            type == MBEDTLS_PK_ECDSA );
}

static int tpm_ecp_verify( void *ctx, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len )
{
    mbedtls_tpm_ecp* self = (mbedtls_tpm_ecp*)ctx;
    mbedtls_ecdsa_context ecdsa_ctx;
    int ret = 0;

    if( md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( md_alg != MBEDTLS_MD_SHA256 )
        return( MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE );


    if( hash_len == 0 )
    {
        const mbedtls_md_info_t *md_info;

        md_info = mbedtls_md_info_from_type( md_alg );
        if( md_info == NULL )
            return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

        hash_len = mbedtls_md_get_size( md_info );
    }

    mbedtls_ecdsa_init( &ecdsa_ctx );

    if( ( ret = mbedtls_ecdsa_from_keypair( &ecdsa_ctx, &self->ecp ) ) != 0 )
        goto error;

    if( ( ret = mbedtls_ecdsa_read_signature( &ecdsa_ctx, hash, hash_len,
                                              sig, sig_len ) ) != 0 )
        goto error;

error:
    mbedtls_ecdsa_free( &ecdsa_ctx );
    return( ret );
}

static int tpm_ecp_sign( void *ctx, mbedtls_md_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng )
{
    (void) f_rng;
    (void) p_rng;
    int ret = 0;
    unsigned char sig_r[32], sig_s[32];
    size_t sig_r_len = sizeof(sig_r), sig_s_len = sizeof(sig_s);
    mbedtls_mpi r, s;

    if( md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( md_alg != MBEDTLS_MD_SHA256 )
        return( MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE );

    if( hash_len == 0 )
    {
        const mbedtls_md_info_t *md_info;

        md_info = mbedtls_md_info_from_type( md_alg );
        if( md_info == NULL )
            return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

        hash_len = mbedtls_md_get_size( md_info );
    }

    if ( tpmapi_wrapped_ecp_sign( tpmapi_convert_ecp_algo( MBEDTLS_PK_ECDSA ),
                                  tpmapi_convert_hash_algo( md_alg ),
                                  hash, hash_len,
                                  sig_r, &sig_r_len, sig_s, &sig_s_len ) )
        return( MBEDTLS_ERR_ECP_INVALID_KEY );

    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );

    if ( mbedtls_mpi_read_binary( &r, sig_r, sig_r_len ) != 0 ||
         mbedtls_mpi_read_binary( &s, sig_s, sig_s_len ) != 0 )
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto error;
    }

    if ( ( ret = ecdsa_signature_to_asn1( &r, &s, sig, sig_len ) ) != 0 )
        goto error;

    return( ret );

error:
    mbedtls_mpi_free( &s );
    mbedtls_mpi_free( &r );

    return( ret );
}

static int tpm_ecp_check_pair( const void *pub, const void *prv )
{
    int ret;
    unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
    unsigned char hash[32] = {0};
    size_t sig_len = sizeof( sig );

    memset( hash, 0x2a, sizeof( hash ) );

    if( ( ret = tpm_ecp_sign( (void *) prv, MBEDTLS_MD_SHA256,
                              hash, sizeof( hash ),
                              sig, &sig_len, NULL, NULL ) ) != 0 )
        return( ret );

    if( ( ret = tpm_ecp_verify( (void *) pub, MBEDTLS_MD_SHA256,
                                hash, sizeof( hash ),
                                sig, sig_len ) ) != 0 )
        return( ret );

    return( ret );
}

static void tpm_ecp_free( void *ctx )
{
    if(ctx != NULL)
    {
        mbedtls_tpm_ecp* self = (mbedtls_tpm_ecp*) ctx;
        mbedtls_ecp_keypair_free( &self->ecp );
        mbedtls_free( ctx );
    }
}

static void *tpm_ecp_alloc( void )
{
    mbedtls_tpm_ecp *ctx = mbedtls_calloc( 1, sizeof( mbedtls_tpm_ecp ) );

    if( ctx == NULL )
        return( NULL );

    return( ctx );
}

static void tpm_ecp_debug( const void *ctx, mbedtls_pk_debug_item *items )
{
    (void) ctx;
    (void) items;
}

int pk_tpm_ecp_init( mbedtls_pk_context *ctx )
{
    int ret = 0;
    unsigned char x[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char y[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char *xy;
    size_t xLen = MBEDTLS_ECDSA_MAX_LEN, yLen = MBEDTLS_ECDSA_MAX_LEN, xyLen;

    if ( ctx != NULL )
    {
        mbedtls_ecp_keypair *kp = (mbedtls_ecp_keypair *) ctx->pk_ctx;

        mbedtls_ecp_keypair_init( kp );

        if( ( ret = mbedtls_ecp_group_load( &kp->grp, MBEDTLS_ECP_DP_SECP256R1 ) ) != 0 )
            return ret;

        if( tpmapi_wrapped_getEcpPk( x, &xLen, y, &yLen ) != 0 )
            return( MBEDTLS_ERR_ECP_HW_ACCEL_FAILED );

        xyLen = 1 + xLen + yLen;
        xy = malloc( xyLen );
        
        xy[0] = 0x4;
        memcpy( &xy[1], x, xLen );
        memcpy( &xy[1 + xLen], y, yLen ); 

        ret = mbedtls_ecp_point_read_binary( &kp->grp, &kp->Q, xy, xyLen );

        free( xy );
    }

    return( ret );
}

const mbedtls_pk_info_t tpm_ecp_info =
{
    MBEDTLS_PK_ECKEY,
    TPM_NAME,
    tpm_ecp_get_bitlen,
    tpm_ecp_can_do,
    tpm_ecp_verify,
    tpm_ecp_sign,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    NULL,
    NULL,
    tpm_ecp_check_pair,
    tpm_ecp_alloc,
    tpm_ecp_free,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    tpm_ecp_debug
};
