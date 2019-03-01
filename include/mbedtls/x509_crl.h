/**
 * \file x509_crl.h
 *
 * \brief X.509 certificate revocation list parsing
 */
/*
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
#ifndef MBEDTLS_X509_CRL_H
#define MBEDTLS_X509_CRL_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "x509.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup x509_module
 * \{ */

/**
 * \name Structures and functions for parsing CRLs
 * \{
 */

/**
 * Certificate revocation list entry.
 * Contains the CA-specific serial numbers and revocation dates.
 */
typedef struct mbedtls_x509_crl_entry
{
    mbedtls_x509_buf raw;

    mbedtls_x509_buf serial;

    mbedtls_x509_time revocation_date;

    mbedtls_x509_buf entry_ext;

    struct mbedtls_x509_crl_entry *next;
}
mbedtls_x509_crl_entry;

/**
 * Certificate revocation list structure.
 * Every CRL may have multiple entries.
 */
typedef struct mbedtls_x509_crl
{
    mbedtls_x509_buf raw;           /**< The raw certificate data (DER). */
    mbedtls_x509_buf tbs;           /**< The raw certificate body (DER). The part that is To Be Signed. */

    int version;            /**< CRL version (1=v1, 2=v2) */
    mbedtls_x509_buf sig_oid;       /**< CRL signature type identifier */

    mbedtls_x509_buf issuer_raw;    /**< The raw issuer data (DER). */

    mbedtls_x509_name issuer;       /**< The parsed issuer data (named information object). */

    mbedtls_x509_time this_update;
    mbedtls_x509_time next_update;

    mbedtls_x509_crl_entry entry;   /**< The CRL entries containing the certificate revocation times for this CA. */

    mbedtls_x509_buf crl_ext;

    mbedtls_x509_buf sig_oid2;
    mbedtls_x509_buf sig;
    mbedtls_md_type_t sig_md;           /**< Internal representation of the MD algorithm of the signature algorithm, e.g. MBEDTLS_MD_SHA256 */
    mbedtls_pk_type_t sig_pk;           /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. MBEDTLS_PK_RSA */
    void *sig_opts;             /**< Signature options to be passed to mbedtls_pk_verify_ext(), e.g. for RSASSA-PSS */

    struct mbedtls_x509_crl *next;
}
mbedtls_x509_crl;

#define MBEDTLS_X509_CRL_VERSION_1              0
#define MBEDTLS_X509_CRL_VERSION_2              1

/**
 * Container for writing a certificate revocation list entry (CRL entry)
 */
typedef struct mbedtls_x509write_crl_entry
{
    mbedtls_mpi serial;
    char revocation_date[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    mbedtls_asn1_named_data *extensions;
    struct mbedtls_x509write_crl_entry *next;
}
mbedtls_x509write_crl_entry;

/**
 * Container for writing a certificate revocation list (CRL)
 */
typedef struct mbedtls_x509write_crl
{
    int version;
    mbedtls_md_type_t md_alg;
    mbedtls_pk_context *issuer_key;
    mbedtls_asn1_named_data *issuer;
    char this_update[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    char next_update[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    mbedtls_x509write_crl_entry *entries;
    mbedtls_asn1_named_data *extensions;
}
mbedtls_x509write_crl;

/**
 * \brief          Parse a DER-encoded CRL and append it to the chained list
 *
 * \param chain    points to the start of the chain
 * \param buf      buffer holding the CRL data in DER format
 * \param buflen   size of the buffer
 *                 (including the terminating null byte for PEM data)
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int mbedtls_x509_crl_parse_der( mbedtls_x509_crl *chain,
                        const unsigned char *buf, size_t buflen );
/**
 * \brief          Parse one or more CRLs and append them to the chained list
 *
 * \note           Multiple CRLs are accepted only if using PEM format
 *
 * \param chain    points to the start of the chain
 * \param buf      buffer holding the CRL data in PEM or DER format
 * \param buflen   size of the buffer
 *                 (including the terminating null byte for PEM data)
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int mbedtls_x509_crl_parse( mbedtls_x509_crl *chain, const unsigned char *buf, size_t buflen );

#if defined(MBEDTLS_FS_IO)
/**
 * \brief          Load one or more CRLs and append them to the chained list
 *
 * \note           Multiple CRLs are accepted only if using PEM format
 *
 * \param chain    points to the start of the chain
 * \param path     filename to read the CRLs from (in PEM or DER encoding)
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int mbedtls_x509_crl_parse_file( mbedtls_x509_crl *chain, const char *path );
#endif /* MBEDTLS_FS_IO */

/**
 * \brief          Returns an informational string about the CRL.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param prefix   A line prefix
 * \param crl      The X509 CRL to represent
 *
 * \return         The length of the string written (not including the
 *                 terminated nul byte), or a negative error code.
 */
int mbedtls_x509_crl_info( char *buf, size_t size, const char *prefix,
                   const mbedtls_x509_crl *crl );

/**
 * \brief          Initialize a CRL (chain)
 *
 * \param crl      CRL chain to initialize
 */
void mbedtls_x509_crl_init( mbedtls_x509_crl *crl );

/**
 * \brief          Unallocate all CRL data
 *
 * \param crl      CRL chain to free
 */
void mbedtls_x509_crl_free( mbedtls_x509_crl *crl );

/* \} name */
/* \} addtogroup x509_module */

#if defined(MBEDTLS_X509_CRL_WRITE_C)
/**
 * \brief           Initialize a CRL writing context
 *
 * \param ctx       CRL context to initialize
 */
void mbedtls_x509write_crl_init( mbedtls_x509write_crl *ctx );

/**
 * \brief           Set the verion for a Certificate Revocation List
 *                  Default: MBEDTLS_X509_CRL_VERSION_2
 *
 * \param ctx       CRL context to use
 * \param version   version to set (MBEDTLS_X509_CRL_VERSION_1 or MBEDTLS_X509_CRL_VERSION_2)
 */
void mbedtls_x509write_crl_set_version( mbedtls_x509write_crl *ctx, int version );

/**
 * \brief           Set the MD algorithm to use for the signature
 *                  (e.g. MBEDTLS_MD_SHA1)
 *
 * \param ctx       CRL context to use
 * \param md_alg    MD algorithm to use
 */
void mbedtls_x509write_crl_set_md_alg( mbedtls_x509write_crl *ctx, mbedtls_md_type_t md_alg );

/**
 * \brief           Set the issuer name for a Certificate Revocation List
 *                  Issuer names should contain a comma-separated list
 *                  of OID types and values:
 *                  e.g. "C=UK,O=ARM,CN=mbed TLS CA"
 *
 * \param ctx           CRL context to use
 * \param issuer_name   issuer name to set
 *
 * \return          0 if issuer name was parsed successfully, or
 *                  a specific error code
 */
int mbedtls_x509write_crl_set_issuer_name( mbedtls_x509write_crl *ctx,
                                   const char *issuer_name );

/**
 * \brief           Set the issuer key used for signing the certificate revocation list
 *
 * \param ctx       CRL context to use
 * \param key       private key to sign with
 */
void mbedtls_x509write_crl_set_issuer_key( mbedtls_x509write_crl *ctx, mbedtls_pk_context *key );

/**
 * \brief           Set the update times for a Certificate Revocation List
 *                  Timestamps should be in string format for UTC timezone
 *                  i.e. "YYYYMMDDhhmmss"
 *                  e.g. "20131231235959" for December 31st 2013
 *                       at 23:59:59
 *
 * \param ctx       CRL context to use
 * \param this_update    this_update timestamp
 * \param next_update    next_update timestamp
 *
 * \return          0 if timestamp was parsed successfully, or
 *                  a specific error code
 */
int mbedtls_x509write_crl_set_update( mbedtls_x509write_crl *ctx, const char *this_update,
                                const char *next_update );

/**
 * \brief           Generic function to add to or replace an extension in the
 *                  CRL
 *
 * \param ctx       CRL context to use
 * \param oid       OID of the extension
 * \param oid_len   length of the OID
 * \param critical  if the extension is critical (per the RFC's definition)
 * \param val       value of the extension OCTET STRING
 * \param val_len   length of the value data
 *
 * \return          0 if successful, or a MBEDTLS_ERR_X509_ALLOC_FAILED
 */
int mbedtls_x509write_crl_set_extension( mbedtls_x509write_crl *ctx,
                                 const char *oid, size_t oid_len,
                                 int critical,
                                 const unsigned char *val, size_t val_len );

#if defined(MBEDTLS_SHA1_C)
/**
 * \brief           Set the authorityKeyIdentifier extension for a CRL
 *                  Requires that mbedtls_x509write_crl_set_issuer_key() has been
 *                  called before
 *
 * \param ctx       CRL context to use
 *
 * \return          0 if successful, or a MBEDTLS_ERR_X509_ALLOC_FAILED
 */
int mbedtls_x509write_crl_set_authority_key_identifier( mbedtls_x509write_crl *ctx );
#endif /* MBEDTLS_SHA1_C */

/**
 * \brief           Set the CRLNumber extension for a CRL
 *
 * \param ctx       CRL context to use
 *
 * \return          0 if successful, or a MBEDTLS_ERR_X509_ALLOC_FAILED
 */
int mbedtls_x509write_crl_set_crl_number( mbedtls_x509write_crl *ctx, const mbedtls_mpi *crl_number );

/**
 * \brief           Add an entry for a revoked certificate
 *
 * \param ctx       CRL context to use
 *
 * \return          0 if entry was added successfully, or
 *                  a specific error code
 */
mbedtls_x509write_crl_entry *mbedtls_x509write_crl_entry_add( mbedtls_x509write_crl *ctx );

/**
 * \brief           Set the serial number for a CRL entry.
 *
 * \param ctx       CRL entry context to use
 * \param serial    serial number to set
 *
 * \return          0 if successful
 */
int mbedtls_x509write_crl_entry_set_serial( mbedtls_x509write_crl_entry *ctx, const mbedtls_mpi *serial );

/**
 * \brief           Set the revokation date for a CRL entry
 *                  Timestamps should be in string format for UTC timezone
 *                  i.e. "YYYYMMDDhhmmss"
 *                  e.g. "20131231235959" for December 31st 2013
 *                       at 23:59:59
 *
 * \param ctx       CRL entry context to use
 * \param revocation_date    revocation_date timestamp
 *
 * \return          0 if timestamp was parsed successfully, or
 *                  a specific error code
 */
int mbedtls_x509write_crl_entry_set_revocation_date( mbedtls_x509write_crl_entry *ctx, const char *revocation_date );

/**
 * \brief           Generic function to add to or replace an extension in a
 *                  CRL entry
 *
 * \param ctx       CRL entry context to use
 * \param oid       OID of the extension
 * \param oid_len   length of the OID
 * \param critical  if the extension is critical (per the RFC's definition)
 * \param val       value of the extension OCTET STRING
 * \param val_len   length of the value data
 *
 * \return          0 if successful, or a MBEDTLS_ERR_X509_ALLOC_FAILED
 */
int mbedtls_x509write_crl_entry_set_extension( mbedtls_x509write_crl_entry *ctx,
                                 const char *oid, size_t oid_len,
                                 int critical,
                                 const unsigned char *val, size_t val_len );

/**
 * \brief           Set the reason extension for a CRL entry
 *
 * \param ctx       CRL entry context to use
 *
 * \return          0 if successful, or a MBEDTLS_ERR_X509_ALLOC_FAILED
 */
int mbedtls_x509write_crl_entry_set_reason( mbedtls_x509write_crl_entry *ctx, int reason );

/**
 * \brief           Free the contents of a CRL write context
 *
 * \param ctx       CRL context to free
 */
void mbedtls_x509write_crl_free( mbedtls_x509write_crl *ctx );

/**
 * \brief           Write a built up certificate revocation list to a X509 DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       certificate revocation list to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 * \param f_rng     RNG function (for signature, see note)
 * \param p_rng     RNG parameter
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 *
 * \note            f_rng may be NULL if RSA is used for signature and the
 *                  signature is made offline (otherwise f_rng is desirable
 *                  for countermeasures against timing attacks).
 *                  ECDSA signatures always require a non-NULL f_rng.
 */
int mbedtls_x509write_crl_der( mbedtls_x509write_crl *ctx, unsigned char *buf, size_t size,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng );

#if defined(MBEDTLS_PEM_WRITE_C)
/**
 * \brief           Write a built up certificate revocation list to a X509 PEM string
 *
 * \param ctx       certificate revocation list to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 * \param f_rng     RNG function (for signature, see note)
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful, or a specific error code
 *
 * \note            f_rng may be NULL if RSA is used for signature and the
 *                  signature is made offline (otherwise f_rng is desirable
 *                  for countermeasures against timing attacks).
 *                  ECDSA signatures always require a non-NULL f_rng.
 */
int mbedtls_x509write_crl_pem( mbedtls_x509write_crl *ctx, unsigned char *buf, size_t size,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng );
#endif /* MBEDTLS_PEM_WRITE_C */
#endif /* MBEDTLS_X509_CRL_WRITE_C */

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_x509_crl.h */
