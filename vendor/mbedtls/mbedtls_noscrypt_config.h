/**
* \file config-suite-b.h
*
* \brief Minimal configuration for TLS NSA Suite B Profile (RFC 6460)
*/
/*
*  Copyright The Mbed TLS Contributors
*  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
*/
/*
* Minimal configuration for TLS NSA Suite B Profile (RFC 6460)
*
* Distinguishing features:
* - no RSA or classic DH, fully based on ECC
* - optimized for low RAM usage
*
* Possible improvements:
* - if 128-bit security is enough, disable secp384r1 and SHA-512
* - use embedded certs in DER format and disable PEM_PARSE_C and BASE64_C
*
* See README.txt for usage instructions.
*/

 /* System support */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME

/* Mbed TLS feature support */

/* Mbed TLS modules */
#define MBEDTLS_MD_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_ENTROPY_C

/* Rules for enabling AES */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC