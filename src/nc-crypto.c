/*
* Copyright (c) 2026 Vaughn Nugent
*
* Package: noscrypt
* File: nc-crypto.c
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

#include "debug.h"
#include "span.h"

/*
* Since were on the producer side we can export our public api 
* functions during debug builds to expose the internal functions testing purposes. 
*/
#if DEBUG
	#ifdef _NC_IS_WINDOWS
		#define _NCC_API __declspec(dllexport)
	#else
		#define _NCC_API __attribute__((visibility("default")))
	#endif /*  _NC_IS_WINDOWS */
#endif

#include "nc-crypto.h"

#ifndef HKDF_IN_BUF_SIZE
	#define HKDF_IN_BUF_SIZE	0x80	
#endif

/*
*  Functions are not forced inline, just suggested.
*  So unless it becomes a performance issue, I will leave
*  most/all impl functions inline and let the compiler 
*  decide.
*/

#define _IMPLSTB static _nc_fn_inline

/*
* Impl .c files may define the following macros for function implementations:
* 
*		_IMPL_SECURE_ZERO_MEMSET			secure memset 0 function
*		_IMPL_CHACHA20_CRYPT				chacha20 cipher function
*		_IMPL_CRYPTO_FIXED_TIME_COMPARE		fixed time compare function
*       _IMPL_AES256_CBC_CRYPT				performs an AES 256 CBC encryption/decryption
* 
* Macros are used to allow the preprocessor to select the correct implementation
* or raise errors if no implementation is defined.
* 
* Implementation functions can assume inputs have been checked/sanitized by the
* calling function, and should return CSTATUS_OK on success, CSTATUS_FAIL on failure.
*/

#define UNREFPARAM(x) (void)(x)

/*
* Prioritize embedded builds with mbedtls
*/
#ifdef MBEDTLS_CRYPTO_LIB
	#include "providers/mbedtls.c"
#endif

/*
* Include openssl as an alternative default 
* implementation
*/
#ifdef OPENSSL_CRYPTO_LIB
	#include "providers/openssl.c"
#endif

/*
* Always include win32 bcrypt fallback on windows systems. Functions
* may be overridden by other implementations. 
*/
#ifdef _NC_IS_WINDOWS
	#include "providers/bcrypt.c"
#endif

/*
* Handle default implementations of secure 
* memset 0 functions for each platform.
*/
#ifndef _IMPL_SECURE_ZERO_MEMSET
   /* only include bzero if libc version greater than 2.25 */
	#if defined(__GLIBC__) && defined(__GLIBC_MINOR__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 25
		/*
		*	When using libc, we can use explicit_bzero
		*	as secure memset implementation.
		* 
		*	https://sourceware.org/glibc/manual/2.39/html_mono/libc.html#Erasing-Sensitive-Data
		*/
		extern void explicit_bzero(void* block, size_t len);
		#define _IMPL_SECURE_ZERO_MEMSET explicit_bzero
	#endif
#endif

/*
* Finally fall back to monocypher to handle some primitives
* that are not provided by other libraries.
*
* Platform specific optimizations are considered
* "better" than monocypher options, so this is
* added as a last resort. Monocypher is "correct"
* and portable, but not optimized for any specific
* platform.
*/
#ifdef NC_ENABLE_MONOCYPHER
	#include "providers/monocypher.c"
#endif

#ifndef  _IMPL_AES256_CBC_CRYPT

	_IMPLSTB cstatus_t _dummyAesFunc(
		cspan_t key,
		cspan_t iv,
		cspan_t input,
		span_t output,
		int flags
	)
	{
		UNREFPARAM(key);
		UNREFPARAM(iv);
		UNREFPARAM(input);
		UNREFPARAM(output);
		UNREFPARAM(flags);

		return CSTATUS_FAIL;
	}

	#define _IMPL_AES256_CBC_CRYPT _dummyAesFunc

#endif

/* Fallback for fixed time comparison for all platforms */
#ifndef _IMPL_CRYPTO_FIXED_TIME_COMPARE

	#pragma message("Warning: No fixed time compare implementation defined, using fallback. This may not be secure on all platforms")

	#define _IMPL_CRYPTO_FIXED_TIME_COMPARE	_fallbackFixedTimeCompare

	/*
	* This implementation is a slightly simplified version of 
	* MBed TLS constant time memcmp function, known to be a 32bit 
	* integer size
	* 
	* - using uint8_t O forces the compiler to use byte instructions 
	* - using volatile A B reads attempts to force the compiler to read data from memory 
	*    during every loop iteration
	* - volatile result and O are stored on the stack and cannot be kept in a 
	*    register across iterations, preventing the compiler from short-circuiting 
	*    the OR of accumulated results
	*
	* MSVC x64 Release verification (v19.44 /O2 /Ob2):
	* - O is spilled to [rsp+18h] and re-read each iteration via movzx
	* - result is spilled to [rsp+8] and re-read each iteration via mov/or/mov
	* - No early exit on comparison result; loop always runs (size) iterations
	* - Input reads use byte-granular movzx, no word-level shortcuts
	* - Pointer arithmetic is hoisted (r10=a-b base, r9 walks B) but memory 
	*   reads are still performed each iteration as required by volatile
	*/

	static uint32_t _fallbackFixedTimeCompare(const uint8_t* a, const uint8_t* b, uint32_t size)
	{
		uint32_t i = 0;
		volatile uint32_t result = 0;
		volatile uint8_t O = 0;
		volatile const uint8_t* A, * B;

		A = (volatile const uint8_t*)a;
		B = (volatile const uint8_t*)b;

		/* Compare each byte */
		for (; i < size; i++)
		{
			/* Handle volatile read */
			O |= (A[i] ^ B[i]);

			result |= O;
		}

		return result;
	}

#endif /* !_IMPL_CRYPTO_FIXED_TIME_COMPARE */

static cstatus_t _computeDigest(cspan_t key, cspan_t data, sha256_t out32, int hmac)
{
	cstatus_t     status		= 0;
	uint32_t      streamFlags	= 0;
	ncc_digest_t  stream;
	span_t        output;

	/* Debug arg validate */	
	DEBUG_ASSERT2(!spanIsNullC(data), "Expected data to be non-null");
	DEBUG_ASSERT2(out32, "Expected hmacOut32 to be non-null");

	/*
	* sizeof(sha256_t) will always be equal to SHA256_DIGEST_SIZE,
	* so so long as the correct type is set, the digest output will always be
	* correct
	*/
	spanInit(&output, out32, sizeof(sha256_t));

	streamFlags = NC_CRYPTO_DIGEST_TYPE_SHA256;

	/* if hmac key is defined, set the hmac flag on create */
	if (spanGetSizeC(key) > 0 || hmac) 
	{
		streamFlags |= NC_CRYPTO_DIGEST_FLAGS_HMAC;
	}	

	status = ncCryptoDigestCreate(&stream, streamFlags);
	if (status != CSTATUS_OK)
	{
		goto Exit;
	}

	status = ncCryptoDigestInit(&stream, key);
	if (status != CSTATUS_OK)
	{
		goto Exit;
	}

	status = ncCryptoDigestUpdate(&stream, data);
	if (status != CSTATUS_OK)
	{
		goto Exit;
	}
	
	status = ncCryptoDigestFinish(&stream, output);

Exit:
	/* Safe to always clean up a stack stream object */
	ncCryptoDigestClose(&stream);
	return status;
}

_NCC_API void ncCryptoSecureZero(void* ptr, uint32_t size)
{
	DEBUG_ASSERT2(ptr != NULL, "Expected ptr to be non-null")

#ifndef _IMPL_SECURE_ZERO_MEMSET
	#error "No secure memset implementation defined"
#endif /* _IMPL_SECURE_ZERO_MEMSET */

	_IMPL_SECURE_ZERO_MEMSET(ptr, size);
}

_NCC_API uint32_t ncCryptoFixedTimeComp(const uint8_t* a, const uint8_t* b, uint32_t size)
{
	DEBUG_ASSERT2(a != NULL, "Expected a to be non-null")
	DEBUG_ASSERT2(b != NULL, "Expected b to be non-null")

#ifndef _IMPL_CRYPTO_FIXED_TIME_COMPARE
	#error "No fixed time compare implementation defined"
#endif /* !_IMPL_CRYPTO_FIXED_TIME_COMPARE */

	return _IMPL_CRYPTO_FIXED_TIME_COMPARE(a, b, size);
}

_NCC_API cstatus_t ncCryptoChacha20(cspan_t key, cspan_t nonce, cspan_t input, span_t output)
{
	DEBUG_ASSERT2(spanGetSizeC(key) == NC_CRYPTO_CHACHA_KEY_SIZE,		"ChaCha key size is not valid");
	DEBUG_ASSERT2(spanGetSizeC(nonce) == NC_CRYPTO_CHACHA_NONCE_SIZE,	"ChaCha nonce size is not valid");

#ifndef _IMPL_CHACHA20_CRYPT
	#error "No chacha20 implementation defined"
#endif /* !_IMPL_CHACHA20_CRYPT */

	return _IMPL_CHACHA20_CRYPT(key, nonce, input, output);
}


#ifndef _DIGSET_STREAM_INTERFACE
	#error "No crypto digest stream interface was defined at compile time. Cannot continue."
#endif

/*
* Internal function implementations that perform
* basic checking and call the correct implementation
* for the desired crypto impl.
* 
* The following functions MUST be assumed to 
* perform basic input validation. Since these apis are 
* internal, debug asserts are used to ensure the
* function has been used correctly.
*/


_NCC_API cstatus_t ncCryptoAes256CBCUpdate(
	cspan_t key,
	cspan_t iv,
	cspan_t input,
	span_t output,
	int flags
)
{
	DEBUG_ASSERT2(spanGetSizeC(key) == NC_CRYPTO_AES_KEY_SIZE, "Expected AES key size to be 32 bytes");
	DEBUG_ASSERT2(spanGetSizeC(iv) == NC_CRYPTO_AES_IV_SIZE, "Expected AES IV size to be 16 bytes");

#ifndef _IMPL_AES256_CBC_CRYPT
	#error "No AES256 CBC encrypt implementation defined"
#endif /* !_IMPL_AES256_CBC_CRYPT */

	return _IMPL_AES256_CBC_CRYPT(key, iv, input, output, flags);
}

_NCC_API uint32_t ncCryptoDigestGetOutputSize(const ncc_digest_t* stream)
{
	DEBUG_ASSERT(stream);

	if (!stream)
	{
		return 0;
	}

	switch (stream->flags & NC_CRYPTO_DIGEST_TYPE_MASK)
	{
	case NC_CRYPTO_DIGEST_TYPE_SHA256:
		return SHA256_DIGEST_SIZE;
	default:
		return 0;
	}
}

_NCC_API cstatus_t ncCryptoHmacSha256(cspan_t key, cspan_t data, sha256_t hmacOut32)
{
	return _computeDigest(key, data, hmacOut32, 1);
}

_NCC_API cstatus_t ncCryptoDigestSha256(cspan_t data, sha256_t digestOut32)
{
	cspan_t key;

	/* Debug arg validate */
	DEBUG_ASSERT2(!spanIsNullC(data), "Expected data to be non-null");
	DEBUG_ASSERT2(digestOut32 != NULL, "Expected digestOut32 to be non-null");

	spanInitC(&key, NULL, 0);

	return _computeDigest(key, data, digestOut32, 0);
}

/*
* The following functions implements the HKDF expand function using an existing
* HMAC function.
*
* This follows the guidance from RFC 5869: https://tools.ietf.org/html/rfc5869
*/

#ifndef HKDF_MIN
	#define HKDF_MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

_NCC_API cstatus_t ncCryptoSha256HkdfExpand(cspan_t prk, cspan_t info, span_t okm)
{
	cstatus_t		result;
	ncc_digest_t	stream;
	cspan_t			tData, counterSpan;
	span_t			tOutput;
	uint32_t		flags = 0, tLen = 0, okmOffset = 0, hashSize = 0;
	uint8_t			counter = 1, t[HKDF_IN_BUF_SIZE];

	/* Debug arg validate */
	DEBUG_ASSERT2(!spanIsNullC(prk), "Expected prk to be non-null");
	DEBUG_ASSERT2(!spanIsNull(okm), "Expected okm to be non-null");

	/*
	* RFC 5869: 2.3
	* "length of output keying material in octets (<= 255 * HashLen)"
	*
	* important as the counter is 1 byte, so it cannot overflow
	*/
	if (spanGetSize(okm) > (uint32_t)(0xFFu * SHA256_DIGEST_SIZE))
	{
		return CSTATUS_FAIL;
	}

	spanInitC(&counterSpan, &counter, sizeof(uint8_t));
	spanInit(&tOutput, NULL, 0);

	ncCryptoSecureZero(t, sizeof(t));

	flags = NC_CRYPTO_DIGEST_TYPE_SHA256 
		| NC_CRYPTO_DIGEST_FLAGS_HMAC 
		| NC_CRYPTO_DIGEST_FLAGS_REUSE;

	result = ncCryptoDigestCreate(&stream, flags);
	if (result != CSTATUS_OK)
	{
		goto Close;
	}

	/* init guards against empty hmac key material */
	
	result = ncCryptoDigestInit(&stream, prk);
	if (result != CSTATUS_OK)
	{
		goto Close;
	}

	result = CSTATUS_FAIL;

	/* Compute T(N) = HMAC(prk, T(n-1) | info | n) */
	while (okmOffset < spanGetSize(okm))
	{
		spanInitC(&tData, t, tLen);

		if (!ncCryptoDigestUpdate(&stream, tData))
		{
			goto Close;
		}

		if (!ncCryptoDigestUpdate(&stream, info))
		{
			goto Close;
		}

		if (!ncCryptoDigestUpdate(&stream, counterSpan))
		{
			goto Close;
		}

		/*
		* Write current hash state to t buffer. It is known
		* that the t buffer must be at least the size of the
		* underlying hash function output.
		*/
		if (!ncCryptoDigestFinish(&stream, tOutput))
		{
			goto Close;
		}

		/* tlen becomes the hash size or remaining okm size */
		tLen = HKDF_MIN(spanGetSize(okm) - okmOffset, SHA256_DIGEST_SIZE);

		DEBUG_ASSERT(tLen <= sizeof(t));

		/* write the T buffer back to okm and advance okmOffset by tLen */
		spanAppend(okm, &okmOffset, t, tLen);

		/* increment counter */
		counter++;

		/* re-initialize the HMAC state for the next iteration */
		if (!ncCryptoDigestInit(&stream, prk))
		{
			goto Close;
		}
	}

	result = CSTATUS_OK;

Close:
	ncCryptoDigestClose(&stream);
	return result;
}
