/*
 *  Certificate revocation list generation
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_X509_CRL_WRITE_C) || \
    !defined(MBEDTLS_X509_CRL_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C) || \
    !defined(MBEDTLS_ERROR_C) || !defined(MBEDTLS_SHA256_C) || \
    !defined(MBEDTLS_PEM_WRITE_C)
int main( void )
{
    mbedtls_printf( "MBEDTLS_X509_CRL_WRITE_C and/or MBEDTLS_X509_CRL_PARSE_C and/or "
            "MBEDTLS_FS_IO and/or MBEDTLS_SHA256_C and/or "
            "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or "
            "MBEDTLS_ERROR_C not defined.\n");
    return( 0 );
}
#else

#include "mbedtls/x509_crt.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#define USAGE_CRT                                                           \
    "    cert_file=%%s         default: (empty)\n"                              \
    "                            If cert_file is specified, cert_serial\n"      \
    "                            is ignored!\n"
#else
#define USAGE_CRT ""
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#define DFL_ISSUER_CRT          ""
#define DFL_CERT_FILE           ""
#define DFL_CERT_SERIAL         ""
#define DFL_ISSUER_KEY          "ca.key"
#define DFL_ISSUER_PWD          ""
#define DFL_OUTPUT_FILENAME     "revoke.crl"
#define DFL_ISSUER_NAME         "CN=CA,O=mbed TLS,C=UK"
#define DFL_THIS_UPDATE         "20010101000000"
#define DFL_NEXT_UPDATE         "20301231235959"
#define DFL_REVOCATION_DATE     "20190101000000"
#define DFL_CRL_NUMBER          "1"
#define DFL_CRL_REASON          0
#define DFL_AUTH_IDENT          1
#define DFL_VERSION             2
#define DFL_DIGEST              MBEDTLS_MD_SHA256

#define USAGE \
    "\n usage: crl_write param=<>...\n"                 \
    "\n acceptable parameters:\n"                       \
    USAGE_CRT                                           \
    "    cert_serial=%%s          default: (empty)\n"   \
    "    issuer_crt=%%s           default: (empty)\n"       \
    "                            If issuer_crt is specified, issuer_name is\n"  \
    "                            ignored!\n"                \
    "    issuer_name=%%s          default: CN=CA,O=mbed TLS,C=UK\n"     \
    "\n"                                                \
    "    issuer_key=%%s           default: ca.key\n"        \
    "    issuer_pwd=%%s           default: (empty)\n"       \
    "    output_file=%%s          default: revoke.crl\n"    \
    "    crl_number=%%s           default: 1\n"             \
    "    this_update=%%s          default: 20010101000000\n"\
    "    next_update=%%s          default: 20301231235959\n"\
    "    md=%%s                   default: SHA256\n"        \
    "                            Supported values:\n"       \
    "                            MD5, SHA1, SHA256, SHA512\n"\
    "    version=%%d              default: 2\n"            \
    "                            Possible values: 1, 2\n"\
    "    authority_identifier=%%s default: 1\n"             \
    "                            Possible values: 0, 1\n"   \
    "                            (Considered for v2 only)\n"\
    "    reason=%%s               default: 0\n"             \
    "                            Possible values: 0 through 10\n" \
    "    revocation_date=%%s      default: (empty)\n"       \
    "\n"

#if defined(MBEDTLS_CHECK_PARAMS)
#define mbedtls_exit            exit
void mbedtls_param_failed( const char *failure_condition,
                           const char *file,
                           int line )
{
    mbedtls_printf( "%s:%i: Input param failed - %s\n",
                    file, line, failure_condition );
    mbedtls_exit( MBEDTLS_EXIT_FAILURE );
}
#endif

/*
 * global options
 */
struct options
{
    const char *issuer_crt;     /* filename of the issuer certificate    */
    const char *cert_file;      /* filename of the certificate to revoke */
    const char *cert_serial;    /* serial of the certificate to revoke   */
    const char *issuer_key;     /* filename of the issuer key file       */
    const char *issuer_pwd;     /* password for the issuer key file      */
    const char *output_file;    /* where to store the constructed CRT    */
    const char *issuer_name;    /* issuer name for certificate           */
    const char *this_update;     /* validity period not before            */
    const char *next_update;      /* validity period not after             */
    const char *crl_number;      /* crl number string                    */
    const char *revocation_date; /* revocation date                      */
    int reason;                 /* reason for revocation                 */
    int authority_identifier;   /* add authority identifier to CRT       */
    int version;                /* CRT version                           */
    mbedtls_md_type_t md;       /* Hash used for signing                 */
} opt;

int write_crl( mbedtls_x509write_crl *crl, const char *output_file,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    int ret;
    FILE *f;
    unsigned char output_buf[4096];
    size_t len = 0;

    memset( output_buf, 0, 4096 );
    if( ( ret = mbedtls_x509write_crl_pem( crl, output_buf, 4096,
                                           f_rng, p_rng ) ) < 0 )
        return( ret );

    len = strlen( (char *) output_buf );

    if( ( f = fopen( output_file, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( output_buf, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}

int main( int argc, char *argv[] )
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_x509_crt issuer_crt;
    mbedtls_pk_context loaded_issuer_key;
    mbedtls_pk_context *issuer_key = &loaded_issuer_key;
    char buf[1024];
    char issuer_name[256];
    int i;
    char *p, *q;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt crt;
#endif
    mbedtls_x509write_crl crl;
    mbedtls_x509write_crl_entry *crl_entry;
    mbedtls_mpi serial;
    mbedtls_mpi crl_number;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_asn1_buf serial_buf;
    const char *pers = "crl example app";

    /*
     * Set to sane values
     */
    mbedtls_x509write_crl_init( &crl );
	mbedtls_x509_crt_init( &issuer_crt );
    mbedtls_pk_init( &loaded_issuer_key );
    mbedtls_mpi_init( &serial );
    mbedtls_mpi_init( &crl_number );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt_init( &crt );
#endif
    memset( buf, 0, 1024 );

    if( argc == 0 )
    {
    usage:
        mbedtls_printf( USAGE );
        goto exit;
    }

    opt.issuer_crt          = DFL_ISSUER_CRT;
    opt.cert_file           = DFL_CERT_FILE;
    opt.cert_serial         = DFL_CERT_SERIAL;
    opt.issuer_key          = DFL_ISSUER_KEY;
    opt.issuer_pwd          = DFL_ISSUER_PWD;
    opt.output_file         = DFL_OUTPUT_FILENAME;
    opt.issuer_name         = DFL_ISSUER_NAME;
    opt.this_update         = DFL_THIS_UPDATE;
    opt.next_update         = DFL_NEXT_UPDATE;
    opt.crl_number          = DFL_CRL_NUMBER;
    opt.version             = DFL_VERSION - 1;
    opt.md                  = DFL_DIGEST;
    opt.reason              = DFL_CRL_REASON;
    opt.authority_identifier = DFL_AUTH_IDENT;
    opt.revocation_date     = DFL_REVOCATION_DATE;

    for( i = 1; i < argc; i++ )
    {

        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "cert_file" ) == 0 )
            opt.cert_file = q;
        else if( strcmp( p, "issuer_key" ) == 0 )
            opt.issuer_key = q;
        else if( strcmp( p, "issuer_pwd" ) == 0 )
            opt.issuer_pwd = q;
        else if( strcmp( p, "issuer_crt" ) == 0 )
            opt.issuer_crt = q;
        else if( strcmp( p, "issuer_name" ) == 0 )
        {
            opt.issuer_name = q;
        }
        else if( strcmp( p, "this_update" ) == 0 )
        {
            opt.this_update = q;
        }
        else if( strcmp( p, "next_update" ) == 0 )
        {
            opt.next_update = q;
        }
        else if( strcmp( p, "revocation_date" ) == 0)
        {
            opt.revocation_date = q;
        }
        else if( strcmp( p, "cert_serial" ) == 0 )
        {
            opt.cert_serial = q;
        }
        else if( strcmp( p, "crl_number" ) == 0 )
        {
            opt.crl_number = q;
        }
        else if( strcmp( p, "authority_identifier" ) == 0 )
        {
            opt.authority_identifier = atoi( q );
            if( opt.authority_identifier != 0 &&
                opt.authority_identifier != 1 )
            {
                mbedtls_printf( "Invalid argument for option %s\n", p );
                goto usage;
            }
        }
        else if( strcmp( p, "md" ) == 0 )
        {
            if( strcmp( q, "SHA1" ) == 0 )
                opt.md = MBEDTLS_MD_SHA1;
            else if( strcmp( q, "SHA256" ) == 0 )
                opt.md = MBEDTLS_MD_SHA256;
            else if( strcmp( q, "SHA512" ) == 0 )
                opt.md = MBEDTLS_MD_SHA512;
            else if( strcmp( q, "MD5" ) == 0 )
                opt.md = MBEDTLS_MD_MD5;
            else
            {
                mbedtls_printf( "Invalid argument for option %s\n", p );
                goto usage;
            }
        }
        else if( strcmp( p, "version" ) == 0 )
        {
            opt.version = atoi( q );
            if( opt.version < 1 || opt.version > 2 )
            {
                mbedtls_printf( "Invalid argument for option %s\n", p );
                goto usage;
            }
            opt.version--;
        }
        else if( strcmp( p, "reason" ) == 0 )
        {
            opt.version = atoi( q );
            if( opt.version < 0 || opt.version > 10 )
            {
                mbedtls_printf( "Invalid argument for option %s\n", p );
            }
        }
        else
            goto usage;
    }

    mbedtls_printf("\n");

    /*
     * 0. Seed the PRNG
     */
    mbedtls_printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_ctr_drbg_seed returned %d - %s\n",
                        ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    // Parse CRL number to MPI
    //
    mbedtls_printf( "  . Reading CRL number..." );
    fflush( stdout );

    if( ( ret = mbedtls_mpi_read_string( &crl_number, 10, opt.crl_number ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_mpi_read_string "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    // Parse issuer certificate if present
    //
    if( strlen( opt.issuer_crt ) )
    {
        /*
         * 1.0.a. Load the issuer certificate
         */
        mbedtls_printf( "  . Loading the issuer certificate ..." );
        fflush( stdout );

        if( ( ret = mbedtls_x509_crt_parse_file( &issuer_crt, opt.issuer_crt ) ) != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse_file "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        ret = mbedtls_x509_dn_gets( issuer_name, sizeof(issuer_name),
                                 &issuer_crt.subject );
        if( ret < 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509_dn_gets "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        opt.issuer_name = issuer_name;

        mbedtls_printf( " ok\n" );
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    // Parse certificate if present
    //
    if( strlen( opt.cert_file ) )
    {
        /*
         * 1.0.b. Load the certificate to revoke
         */
        mbedtls_printf( "  . Loading the certificate ..." );
        fflush( stdout );

        if( ( ret = mbedtls_x509_crt_parse_file( &crt, opt.cert_file ) ) != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509_csr_parse_file "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        memcpy( &serial_buf, &crt.serial, sizeof(mbedtls_asn1_buf) );
        ret = mbedtls_mpi_read_binary( &serial, serial_buf.p, serial_buf.len );

        if( ret < 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }
#endif /* MBEDTLS_X509_CSR_PARSE_C */

    /*
     * 1.1. Parse serial number
     */
    if( !strlen( opt.cert_file ) )
    {
        mbedtls_printf( "  . Loading the serial number ..." );
        fflush( stdout );

        if( ( ret = mbedtls_mpi_read_string( &serial, 10, opt.cert_serial ) ) != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_mpi_read_string "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }

    mbedtls_printf( "  . Loading the issuer key ..." );
    fflush( stdout );

    ret = mbedtls_pk_parse_keyfile( &loaded_issuer_key, opt.issuer_key,
                             opt.issuer_pwd );
    if( ret != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_keyfile "
                        "returned -x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    // Check if key and issuer certificate match
    //
    if( strlen( opt.issuer_crt ) )
    {
        if( mbedtls_pk_check_pair( &issuer_crt.pk, issuer_key ) != 0 )
        {
            mbedtls_printf( " failed\n  !  issuer_key does not match "
                            "issuer certificate\n\n" );
            goto exit;
        }
    }

    mbedtls_printf( " ok\n" );

    mbedtls_x509write_crl_set_issuer_key( &crl, issuer_key );

    /*
     * 1.2. Check the names for validity
     */
    if( ( ret = mbedtls_x509write_crl_set_issuer_name( &crl, opt.issuer_name ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crl_set_issuer_name "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    mbedtls_printf( "  . Setting certificate revocation list values ..." );
    fflush( stdout );

    mbedtls_x509write_crl_set_version( &crl, opt.version );
    mbedtls_x509write_crl_set_md_alg( &crl, opt.md );

    ret = mbedtls_x509write_crl_set_update( &crl, opt.this_update, opt.next_update );
    if( ret != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crl_set_update "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    if( opt.version == MBEDTLS_X509_CRL_VERSION_2 )
    {
        ret = mbedtls_x509write_crl_set_crl_number( &crl, &crl_number );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509write_crl_set_crl_number "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }
    }

    mbedtls_printf( " ok\n" );

#if defined(MBEDTLS_SHA1_C)
    if( opt.version == MBEDTLS_X509_CRL_VERSION_2 &&
        opt.authority_identifier != 0 )
    {
        mbedtls_printf( "  . Adding the Authority Key Identifier ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crl_set_authority_key_identifier( &crl );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509write_crl_set_authority_"
                            "key_identifier returned -0x%04x - %s\n\n",
                            -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }
#endif /* MBEDTLS_SHA1_C */

    /*
     * 1.3. Add to revocation list
     */
    mbedtls_printf( "  . Revoking certificate... " );
    fflush( stdout );

    crl_entry = mbedtls_x509write_crl_entry_add( &crl );

    if( crl_entry == NULL )
    {
        mbedtls_strerror( MBEDTLS_ERR_X509_ALLOC_FAILED, buf, 1024 );
        mbedtls_printf( " failed\n !  mbedtls_x509write_crl_entry_add -0x%04x - %s\n\n",
                        -MBEDTLS_ERR_X509_ALLOC_FAILED, buf );
        goto exit;
    }

    if( ( ret = mbedtls_x509write_crl_entry_set_serial( crl_entry, &serial ) ) != 0)
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n !  mbedtls_x509write_crl_entry_set_serial -0x%04x - %s\n\n",
                        -ret, buf );
        goto exit;
    }

    if( ( ret = mbedtls_x509write_crl_entry_set_revocation_date( crl_entry, opt.revocation_date ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n !  mbedtls_x509write_crl_entry_set_revocation_date -0x%04x - %s\n\n",
                        -ret, buf );
        goto exit;
    }

    if( ( ret = mbedtls_x509write_crl_entry_set_reason( crl_entry, opt.reason ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n !  mbedtls_x509write_crl_entry_set_reason -0x%04x - %s\n\n",
                        -ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 1.x. Writing the certificate
     */
    mbedtls_printf( "  . Writing the certificate revocation list..." );
    fflush( stdout );

    if( ( ret = write_crl( &crl, opt.output_file,
                                   mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  write_crl -0x%04x - %s\n\n",
                        -ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt_free( &crt );
#endif /* MBEDTLS_X509_CSR_PARSE_C */
    mbedtls_x509_crt_free( &issuer_crt );
    mbedtls_x509write_crl_free( &crl );
    mbedtls_pk_free( &loaded_issuer_key );
    mbedtls_mpi_free( &serial );
    mbedtls_mpi_free( &crl_number );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( exit_code );
}
#endif /* MBEDTLS_X509_CRT_WRITE_C && MBEDTLS_X509_CRT_PARSE_C &&
          MBEDTLS_FS_IO && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C &&
          MBEDTLS_ERROR_C && MBEDTLS_PEM_WRITE_C */
