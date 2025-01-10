/*
* Copyright (c) 2025 Vaughn Nugent
*
* Package: noscrypt
* File: providers/mbedtls.c
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


/*
* This file contains implemntation functions for the required 
* cryptography primitives of noscrypt. This file stubs functionality
* using the Mbed-TLS library, if the builder desires to link against
* it. 
*/

#ifdef MBEDTLS_CRYPTO_LIB

/* Inline errors on linux in header files on linux */
#ifndef inline
	#define inline __inline
	#include <mbedtls/mbedtls/md.h>
	#include <mbedtls/mbedtls/hkdf.h>
	#include <mbedtls/mbedtls/hmac_drbg.h>
	#include <mbedtls/mbedtls/sha256.h>
	#include <mbedtls/mbedtls/chacha20.h>
	#include <mbedtls/mbedtls/constant_time.h>
	#undef inline
#else
	#include <mbedtls/mbedtls/md.h>
	#include <mbedtls/mbedtls/hkdf.h>
	#include <mbedtls/mbedtls/hmac_drbg.h>
	#include <mbedtls/mbedtls/sha256.h>
	#include <mbedtls/mbedtls/chacha20.h>
	#include <mbedtls/mbedtls/constant_time.h>
#endif

_IMPLSTB const mbedtls_md_info_t* _mbed_sha256_alg(void)
{
	const mbedtls_md_info_t* info;
	/* Get sha256 md info for hdkf operations */
	info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	DEBUG_ASSERT2(info != NULL, "Expected SHA256 md info pointer to be valid")
	return info;
}

/*
* Guard against size_t overflow for platforms with
* integer sizes less than 32 bits.
*/
#if SIZE_MAX < UINT32_MAX
	#define _ssize_guard_int(x) if(__isLargerThanPlatformIntSize(x)) return CSTATUS_FAIL;

	_IMPLSTB int __isLargerThanPlatformIntSize(uint32_t x)
	{
		return x > SIZE_MAX;
	}

#else
	#define _ssize_guard_int(x)
	#define __isLargerThanPlatformIntSize(x) 0
#endif

#ifndef _IMPL_CHACHA20_CRYPT
	
	/* Export chacha20 computation */
	#define _IMPL_CHACHA20_CRYPT _mbed_chacha20_encrypt	

	_IMPLSTB cstatus_t _mbed_chacha20_encrypt(
		cspan_t key,
		cspan_t nonce,
		cspan_t input,
		span_t output
	)
	{
		_ssize_guard_int(input.size);

		/* Ensure output buffer is large enough to store input data */
		if (ncSpanGetSize(output) < ncSpanGetSizeC(input))
		{
			return CSTATUS_FAIL;
		}

		/* Counter always starts at 0 */
		return mbedtls_chacha20_crypt(
			ncSpanGetOffsetC(key, 0),
			ncSpanGetOffsetC(nonce, 0),
			0x00u,		/* nip-44 counter version */
			ncSpanGetSizeC(input),
			ncSpanGetOffsetC(input, 0), 
			ncSpanGetOffset(output, 0)
		) == 0 ? CSTATUS_OK : CSTATUS_FAIL;
	}

#endif

/* Export sha256 if not already defined */
#ifndef _IMPL_CRYPTO_SHA256_DIGEST	
	
	#define _IMPL_CRYPTO_SHA256_DIGEST			_mbed_sha256_digest	

	_IMPLSTB cstatus_t _mbed_sha256_digest(cspan_t data, sha256_t digestOut32)
	{
		_ssize_guard_int(data.size)

		return mbedtls_sha256(
			ncSpanGetOffsetC(data, 0), 
			ncSpanGetSizeC(data), 
			digestOut32, 
			0				/* Set 0 for sha256 mode */
		) == 0 ? CSTATUS_OK : CSTATUS_FAIL;
	}

#endif

/* Export Sha256 hmac if not already defined by other libs */
#ifndef _IMPL_CRYPTO_SHA256_HMAC

	#define _IMPL_CRYPTO_SHA256_HMAC			_mbed_sha256_hmac

	_IMPLSTB cstatus_t _mbed_sha256_hmac(cspan_t key, cspan_t data, sha256_t hmacOut32)
	{
		_ssize_guard_int(data.size)

		return mbedtls_md_hmac(
			_mbed_sha256_alg(),
			ncSpanGetOffsetC(key, 0), 
			ncSpanGetSizeC(key),
			ncSpanGetOffsetC(data, 0), 
			ncSpanGetSizeC(data),
			hmacOut32
		) == 0 ? CSTATUS_OK : CSTATUS_FAIL;
	}
#endif

/* Export hkdf expand if not already defined */
#ifndef _IMPL_CRYPTO_SHA256_HKDF_EXPAND

	#define _IMPL_CRYPTO_SHA256_HKDF_EXPAND		_mbed_sha256_hkdf_expand

	_IMPLSTB cstatus_t _mbed_sha256_hkdf_expand(cspan_t prk, cspan_t info, span_t okm)
	{		
		_ssize_guard_int(prk.size);
		_ssize_guard_int(info.size);
		_ssize_guard_int(okm.size);

		return mbedtls_hkdf_expand(
			_mbed_sha256_alg(),
			ncSpanGetOffsetC(prk, 0), 
			ncSpanGetSizeC(prk),
			ncSpanGetOffsetC(info, 0),
			ncSpanGetSizeC(info),
			ncSpanGetOffset(okm, 0),
			ncSpanGetSize(okm)
		) == 0 ? CSTATUS_OK : CSTATUS_FAIL;
	}

#endif

/* Export fixed-time compare if not already defined */
#ifndef _IMPL_CRYPTO_FIXED_TIME_COMPARE

	#define _IMPL_CRYPTO_FIXED_TIME_COMPARE		_mbed_fixed_time_compare

	/* fixed-time memcmp */
	_IMPLSTB uint32_t _mbed_fixed_time_compare(const uint8_t* a, const uint8_t* b, uint32_t size)
	{
		/*
		* guard platform int overflow, and forcibly return
		* 1 to indicate failure
		*/
		if (__isLargerThanPlatformIntSize(size))
		{
			return 1;
		}

		return (uint32_t)mbedtls_ct_memcmp(a, b, size);
	}
#endif

#endif