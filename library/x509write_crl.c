/*
 *  X.509 Certidicate Revocation List (CRL) writing
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 *  http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_X509_CRL_WRITE_C)

#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/sha1.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#if defined(MBEDTLS_PEM_WRITE_C)
#include "mbedtls/pem.h"
#endif /* MBEDTLS_PEM_WRITE_C */

void mbedtls_x509write_crl_init( mbedtls_x509write_crl *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_x509write_crl ) );

    ctx->version = MBEDTLS_X509_CRL_VERSION_2;
}

static void x509write_crl_entry_free( mbedtls_x509write_crl_entry *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_mpi_free( &ctx->serial );
    mbedtls_asn1_free_named_data_list( &ctx->extensions );
}

void mbedtls_x509write_crl_free( mbedtls_x509write_crl *ctx )
{
    mbedtls_x509write_crl_entry **head;
    mbedtls_x509write_crl_entry *cur;

    mbedtls_asn1_free_named_data_list( &ctx->issuer );
    mbedtls_asn1_free_named_data_list( &ctx->extensions );

    *head = ctx->entries;

    while( ( cur = *head ) != NULL )
    {
        *head = cur->next;
        x509write_crl_entry_free(cur);
        mbedtls_free( cur );
    }
}

void mbedtls_x509write_crl_set_version( mbedtls_x509write_crl *ctx, int version )
{
    ctx->version = version;
}

void mbedtls_x509write_crl_set_md_alg( mbedtls_x509write_crl *ctx, mbedtls_md_type_t md_alg )
{
    ctx->md_alg = md_alg;
}

int mbedtls_x509write_crl_set_issuer_name( mbedtls_x509write_crl *ctx,
                                   const char *issuer_name )
{
    return mbedtls_x509_string_to_names( &ctx->issuer, issuer_name );
}

void mbedtls_x509write_crl_set_issuer_key( mbedtls_x509write_crl *ctx, mbedtls_pk_context *key )
{
    ctx->issuer_key = key;
}

int mbedtls_x509write_crl_set_update( mbedtls_x509write_crl *ctx, const char *this_update,
                                const char *next_update )
{
    if( strlen( this_update ) != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1 ||
        strlen( next_update )  != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1 )
    {
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );
    }
    strncpy( ctx->this_update, this_update, MBEDTLS_X509_RFC5280_UTC_TIME_LEN );
    strncpy( ctx->next_update , next_update , MBEDTLS_X509_RFC5280_UTC_TIME_LEN );
    ctx->this_update[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';
    ctx->next_update[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';

    return( 0 );
}

int mbedtls_x509write_crl_set_extension( mbedtls_x509write_crl *ctx,
                                 const char *oid, size_t oid_len,
                                 int critical,
                                 const unsigned char *val, size_t val_len )
{
    return mbedtls_x509_set_extension( &ctx->extensions, oid, oid_len,
                               critical, val, val_len );
}

mbedtls_x509write_crl_entry *mbedtls_x509write_crl_entry_add( mbedtls_x509write_crl *ctx )
{
    mbedtls_x509write_crl_entry *cur;

    cur = (mbedtls_x509write_crl_entry *)mbedtls_calloc( 1,
                                             sizeof(mbedtls_x509write_crl_entry) );

    if ( cur == NULL )
        return( NULL );

    cur->next = ctx->entries;
    ctx->entries = cur;

    mbedtls_mpi_init(&cur->serial);

    return( cur );
}

int mbedtls_x509write_crl_entry_set_serial( mbedtls_x509write_crl_entry *ctx, const mbedtls_mpi *serial )
{
    int ret;

    if( ( ret = mbedtls_mpi_copy( &ctx->serial, serial ) ) != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_x509write_crl_entry_set_revocation_date( mbedtls_x509write_crl_entry *ctx, const char *revocation_date )
{
    if( strlen( revocation_date ) != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1 )
    {
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );
    }
    strncpy( ctx->revocation_date, revocation_date, MBEDTLS_X509_RFC5280_UTC_TIME_LEN );
    ctx->revocation_date[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';

    return( 0 );
}

int mbedtls_x509write_crl_entry_set_extension( mbedtls_x509write_crl_entry *ctx,
                                 const char *oid, size_t oid_len,
                                 int critical,
                                 const unsigned char *val, size_t val_len )
{
    return mbedtls_x509_set_extension( &ctx->extensions, oid, oid_len,
                               critical, val, val_len );
}

static int x509_write_crl_entry( unsigned char **p, unsigned char *start, mbedtls_x509write_crl_entry* cur_entry )
{
    int ret;
    size_t len = 0;

    /*
     *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_x509_write_extensions( p, start, cur_entry->extensions ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                       MBEDTLS_ASN1_SEQUENCE ) );

    /*
     * revocationDate ::= Time
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_x509_write_time( p, start, cur_entry->revocation_date,
                                        MBEDTLS_X509_RFC5280_UTC_TIME_LEN ) );

    /*
     *  User Certificate   ::=  INTEGER
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( p, start, &cur_entry->serial ) );

    return( (int)len );
}

static int x509_write_crl_entries( unsigned char **p, unsigned char *start,
                              mbedtls_x509write_crl_entry *first )
{
    int ret;
    size_t len = 0;
    mbedtls_x509write_crl_entry *cur = first;

    while( cur != NULL )
    {
        MBEDTLS_ASN1_CHK_ADD( len, x509_write_crl_entry( p, start, cur ) );
        cur = cur->next;
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                 MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}

int mbedtls_x509write_crl_der( mbedtls_x509write_crl *ctx, unsigned char *buf, size_t size,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    int ret;
    const char *sig_oid;
    size_t sig_oid_len = 0;
    unsigned char *c, *c2;
    unsigned char hash[64];
    unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
    unsigned char tmp_buf[2048];
    size_t sub_len = 0, pub_len = 0, sig_and_oid_len = 0, sig_len;
    size_t len = 0;
    mbedtls_pk_type_t pk_alg;

    c = tmp_buf + sizeof( tmp_buf );

    if( mbedtls_pk_can_do( ctx->issuer_key, MBEDTLS_PK_RSA ) )
        pk_alg = MBEDTLS_PK_RSA;
    else if( mbedtls_pk_can_do( ctx->issuer_key, MBEDTLS_PK_ECDSA ) )
        pk_alg = MBEDTLS_PK_ECDSA;
    else
        return( MBEDTLS_ERR_X509_INVALID_ALG );

    if( ( ret = mbedtls_oid_get_oid_by_sig_alg( pk_alg, ctx->md_alg,
                                          &sig_oid, &sig_oid_len ) ) != 0 )
    {
        return( ret );
    }

    /*
     *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     */

    /* extensions require version 2 */
    if( ctx->version == 1 )
    {
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_x509_write_extensions( &c, tmp_buf, ctx->extensions ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                           MBEDTLS_ASN1_SEQUENCE ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                           MBEDTLS_ASN1_CONSTRUCTED ) );
    }

    /*
     * Revoked Certificates  ::=  SEQUENCE SIZE (1..MAX) OF SEQUENCE
     */

    if( ctx->entries != NULL )
    {
        sub_len = 0;
        MBEDTLS_ASN1_CHK_ADD( sub_len, x509_write_crl_entries( &c, tmp_buf, ctx->entries ) );
        len += sub_len;
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, sub_len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                           MBEDTLS_ASN1_SEQUENCE ) );
    }

    /*
     * nextUpdate ::= Time
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_x509_write_time( &c, tmp_buf, ctx->next_update,
                                        MBEDTLS_X509_RFC5280_UTC_TIME_LEN ) );

    /*
     * thisUpdate ::= Time
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_x509_write_time( &c, tmp_buf, ctx->this_update,
                                        MBEDTLS_X509_RFC5280_UTC_TIME_LEN ) );

    /*
     *  Issuer  ::=  Name
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_x509_write_names( &c, tmp_buf, ctx->issuer ) );

    /*
     * Signature ::= AlgorithmIdentifier
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( &c, tmp_buf,
                       sig_oid, strlen( sig_oid ), 0 ) );

    /*
     * version ::= INTEGER  {  v1(0), v2(1)  }
     */

    /* version is only printed for version 2 */
    if( ctx->version == 1 )
    {
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( &c, tmp_buf, ctx->version ) );
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, tmp_buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, tmp_buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                       MBEDTLS_ASN1_SEQUENCE ) );

    /*
     * Make signature
     */
    if( ( ret = mbedtls_md( mbedtls_md_info_from_type( ctx->md_alg ), c,
                            len, hash ) ) != 0 )
    {
        return( ret );
    }

    if( ( ret = mbedtls_pk_sign( ctx->issuer_key, ctx->md_alg, hash, 0, sig, &sig_len,
                         f_rng, p_rng ) ) != 0 )
    {
        return( ret );
    }

    /*
     * Write data to output buffer
     */
    c2 = buf + size;
    MBEDTLS_ASN1_CHK_ADD( sig_and_oid_len, mbedtls_x509_write_sig( &c2, buf,
                                        sig_oid, sig_oid_len, sig, sig_len ) );

    if( len > (size_t)( c2 - buf ) )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    c2 -= len;
    memcpy( c2, c, len );

    len += sig_and_oid_len;
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c2, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c2, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                 MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}

#define PEM_BEGIN_CRL           "-----BEGIN X509 CRL-----\n"
#define PEM_END_CRL             "-----END X509 CRL-----\n"

#if defined(MBEDTLS_PEM_WRITE_C)
int mbedtls_x509write_crl_pem( mbedtls_x509write_crl *ctx, unsigned char *buf, size_t size,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    int ret;
    unsigned char output_buf[4096];
    size_t olen = 0;

    if( ( ret = mbedtls_x509write_crl_der( ctx, output_buf, sizeof(output_buf),
                                   f_rng, p_rng ) ) < 0 )
    {
        return( ret );
    }

    if( ( ret = mbedtls_pem_write_buffer( PEM_BEGIN_CRL, PEM_END_CRL,
                                  output_buf + sizeof(output_buf) - ret,
                                  ret, buf, size, &olen ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}
#endif /* MBEDTLS_PEM_WRITE_C */

#endif /* MBEDTLS_X509_CRL_WRITE_C */
