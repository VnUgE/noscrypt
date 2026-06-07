
/*
* Copyright (c) 2026 Vaughn Nugent
*
* Package: noscrypt
* File: nc-crypto.h
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public License
* as published by the Free Software Foundation; either version 2.1
* of the License, or  (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with noscrypt. If not, see http://www.gnu.org/licenses/.
*/

#pragma once

#ifndef _NC_CRYPTO_H
#define _NC_CRYPTO_H

#include <stdint.h>
#include <platform.h>
#include "span.h"

/*
* Optionally sets the function visibility. Defaults to internal 
(not exposed in public interface). Useful for testing purposes.
*/
#ifndef _NCC_API
	#define _NCC_API
#endif /* !_NCC_API */


#define NC_CRYPTO_CHACHA_NONCE_SIZE		0x0cu		/* Size of 12 is set by the cipher spec */
#define NC_CRYPTO_CHACHA_KEY_SIZE		0x20u		/* Size of 32 is set by the cipher spec */
#define SHA256_DIGEST_SIZE				0x20u		/* Size of 32 is set by the cipher spec */
#define NC_CRYPTO_AES_IV_SIZE			0x10u		/* CBC IV size matches the AES block size of 128 */
#define NC_CRYPTO_AES_KEY_SIZE			0x20u		/* AES 256 key size */

#define NC_CRYPTO_AES_MODE_DECRYPT		0x00u
#define NC_CRYPTO_AES_MODE_ENCRYPT		0x01u

/*
*     digest stream constants/flags
* ===============================================
*/

/* Used to mask off the mode bits */
#define NC_CRYPTO_DIGEST_FLAGS_MASK     0x000fu
/* set by Create() when stream is ready for use */
#define NC_CRYPTO_DIGEST_FLAGS_READY    0x0001u
/* Enables MAC stream mode */
#define NC_CRYPTO_DIGEST_FLAGS_HMAC     0x0002u
/* Configures the stream as reusable */
#define NC_CRYPTO_DIGEST_FLAGS_REUSE    0x0004u

/* 
* Digest type is a nibble before the flag bits
* that gives us 4 bits to define other types,
* probably only need 3 bits instead.
*/

#define NC_CRYPTO_DIGEST_TYPE_MASK      0x00f0u  
#define NC_CRYPTO_DIGEST_TYPE_SHA256    0x0010u

/* =============================================== */

typedef uint8_t cstatus_t;
#define CSTATUS_OK				((cstatus_t)0x01u)
#define CSTATUS_FAIL			((cstatus_t)0x00u)

typedef uint8_t sha256_t[SHA256_DIGEST_SIZE];


_NCC_API uint32_t ncCryptoFixedTimeComp(const uint8_t* a, const uint8_t* b, uint32_t size);

_NCC_API void ncCryptoSecureZero(void* ptr, uint32_t size);

_NCC_API cstatus_t ncCryptoHmacSha256(cspan_t key, cspan_t data, sha256_t hmacOut32);

_NCC_API cstatus_t ncCryptoDigestSha256(cspan_t data, sha256_t digestOut32);

_NCC_API cstatus_t ncCryptoSha256HkdfExpand(cspan_t prk, cspan_t info, span_t okm);

_NCC_API cstatus_t ncCryptoChacha20(cspan_t key, cspan_t nonce, cspan_t input, span_t output);

_NCC_API cstatus_t ncCryptoAes256CBCUpdate(
	cspan_t key,
	cspan_t iv,
	cspan_t input,
	span_t output,
	int flags
);

/*
* The digest stream cycle is designed to imitate the OpenSSL EVP interface state 
* cycle. 
* 
* https://docs.openssl.org/3.0/man7/life_cycle-mac
* 
*	created -> initialized -> updated -> finished -> closed
* 
* Creation is a constructive/destructive event preparing reusable stream handles 
* for initialization and use until freed. 
* 
* Digest streams can be configured to be reusable (or not, default) where the lifecycle goes 
*	 created -> (init -> updated -> finished) * N times -> closed
*/

/* 
 * Define the digest context type
 * Includes headers that define the required crypto digest context type
*/
#if defined(MBEDTLS_CRYPTO_LIB)
	#include <mbedtls/md.h>
	#define _ncc_digest_ctx_t mbedtls_md_context_t
#elif defined(OPENSSL_CRYPTO_LIB)
	#include <openssl/crypto.h>
	#include <openssl/evp.h>
	
	struct _ncc_ossl_digest_ctx {
		void* _context;
		void* _providerHandle;
	};

	#define _ncc_digest_ctx_t struct _ncc_ossl_digest_ctx
#elif defined(_NC_IS_WINDOWS)
	struct _ncc_bcrypt_digest_stream {
		void* hAlg;
		void* hHash;
	};

	#define _ncc_digest_ctx_t struct _ncc_bcrypt_digest_stream
#else
	#error "No ncc_digest_ctx_t defined for this platform. Cannot continue"
#endif

typedef struct nc_crypto_digest {
	uint32_t flags;
	uint32_t _reserved;
	_ncc_digest_ctx_t ctx;
} ncc_digest_t;

/*
* @param stream A pointer to an un-initialized stream structure to setup
* @param flags A uint32 value set 
* @return A positive value (or CSTATUS_OK) if successful 0 CSTATUS_FAIL otherwise
*/
_NCC_API cstatus_t ncCryptoDigestCreate(ncc_digest_t* stream, uint32_t flags);

/*
* @param stream A pointer to the initialized stream object to initialize
* @return A positive value (or CSTATUS_OK) if successful 0 CSTATUS_FAIL otherwise
*/
_NCC_API cstatus_t ncCryptoDigestInit(ncc_digest_t* stream, cspan_t hmacKey);

/*
* @param stream A pointer to the initialized stream object to update
* @return A positive value (or CSTATUS_OK) if successful 0 CSTATUS_FAIL otherwise
*/
_NCC_API cstatus_t ncCryptoDigestUpdate(ncc_digest_t* stream, cspan_t source);

/*
* Writes the accumulated digest value to the output buffer. 
* NOTE! You must ensure the output buffer is the correct size using ncCryptoDigestGetOutputSize(). 
* This function simply passes the output buffer to the underlying digest api. 
* @param stream A pointer to the initialized stream object to finish
* @param output A span holding the output buffer to write the output data to
* @return A positive value (or CSTATUS_OK) if successful 0 CSTATUS_FAIL otherwise
*/
_NCC_API cstatus_t ncCryptoDigestFinish(ncc_digest_t* stream, span_t output);

/*
* Unconditionally attempts to close/destroy the stream state. Noop if the stream pointer is null. 
* Always performs ncCryptoSecureZero on the stream structure to wipe all fields and reset.
* @param stream A pointer to the stream to cloze/zero. 
*/
_NCC_API void ncCryptoDigestClose(ncc_digest_t* stream);

/*
* Gets the size (in bytes) of the size of the digest output buffer required to store the hash value.
* @param stream A pointer to an initialized digest stream
* @return The size (in bytes) of digest or 0 if the stream is invalid
*/
_NCC_API uint32_t ncCryptoDigestGetOutputSize(const ncc_digest_t* stream);

static _nc_fn_inline cstatus_t ncCryptoSha256HkdfExtract(cspan_t salt, cspan_t ikm, sha256_t prk)
{
	DEBUG_ASSERT2(!spanIsNullC(ikm), "Expected ikm to be non-null");
	DEBUG_ASSERT2(prk, "Expected prk to be non-null");	

	return ncCryptoHmacSha256(salt, ikm, prk);
}

#endif /* !_NC_CRYPTO_H */
