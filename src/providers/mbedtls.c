/*
* Copyright (c) 2026 Vaughn Nugent
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
* This file contains implementation functions for the required 
* cryptography primitives of noscrypt. This file stubs functionality
* using the Mbed-TLS library, if the builder desires to link against
* it. 
*/

/* Inline errors on Linux in header files */
#ifndef inline
	#define inline __inline
	#include <mbedtls/md.h>
	#include <mbedtls/aes.h>
	#include <mbedtls/chacha20.h>
	#include <mbedtls/constant_time.h>
	#undef inline
#else
	#include <mbedtls/md.h>
	#include <mbedtls/aes.h>
	#include <mbedtls/chacha20.h>
	#include <mbedtls/constant_time.h>
#endif

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
		if (spanGetSize(output) < spanGetSizeC(input))
		{
			return CSTATUS_FAIL;
		}

		/* Counter always starts at 0 */
		return mbedtls_chacha20_crypt(
			spanGetOffsetC(key, 0),
			spanGetOffsetC(nonce, 0),
			0x00u,		/* nip-44 counter version */
			spanGetSizeC(input),
			spanGetOffsetC(input, 0), 
			spanGetOffset(output, 0)
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

/*
* Export the ncCrypto digest interface function overrides for mbedtls
*/
#ifndef _DIGSET_STREAM_INTERFACE

	#define _DIGSET_STREAM_INTERFACE "mbedtls"

	void ncCryptoDigestClose(ncc_digest_t* stream)
	{
		DEBUG_ASSERT(stream);
		if (stream)
		{
			mbedtls_md_free(&stream->ctx);

			/* clear out the digest */
			ncCryptoSecureZero(stream, sizeof(ncc_digest_t));
		}
	}

	cstatus_t ncCryptoDigestCreate(ncc_digest_t* stream, uint32_t flags)
	{		
		const mbedtls_md_info_t* mdInfo;

		DEBUG_ASSERT(stream);
		if (!stream)
		{
			return CSTATUS_FAIL;
		}

		/*
		* Generic bit flags sit on the lowest 8 bits, next is the
		* digest type value. The mask will clear all bits except
		* the digest nibble
		*/
		switch (flags & NC_CRYPTO_DIGEST_TYPE_MASK)
		{
		case NC_CRYPTO_DIGEST_TYPE_SHA256:
			mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
			break;

		default:
			return CSTATUS_FAIL;
		}

		/* literally just calls memset() */
		mbedtls_md_init(&stream->ctx);

		/* 
		* Setup the context. flags & hmac == 0 no hmac, != 0 enables hmac
		*/
		if (mbedtls_md_setup(&stream->ctx, mdInfo, (flags & NC_CRYPTO_DIGEST_FLAGS_HMAC)) == 0)
		{
			stream->flags = (flags | NC_CRYPTO_DIGEST_FLAGS_READY);
			return CSTATUS_OK;
		}

		/* Supposed to call close anytime after setup is called */
		ncCryptoDigestClose(stream);
		return CSTATUS_FAIL;
	}

	cstatus_t ncCryptoDigestInit(ncc_digest_t* stream, cspan_t hmacKey)
	{
		int result;		

		DEBUG_ASSERT(stream);
		if (!stream)
		{
			return CSTATUS_FAIL;
		}

		_ssize_guard_int(spanGetSizeC(hmacKey))

		/* use hmac if stream is set hmac flags */
		if (stream->flags & NC_CRYPTO_DIGEST_FLAGS_HMAC)
		{
			result = mbedtls_md_hmac_starts(
				&stream->ctx,
				spanGetOffsetC(hmacKey, 0),
				(size_t)spanGetSizeC(hmacKey)
			);
		}
		/* otherwise normal digest initialization */
		else
		{
			result = mbedtls_md_starts(&stream->ctx);
		}
	
		return result == 0 ? CSTATUS_OK : CSTATUS_FAIL;
	}

	cstatus_t ncCryptoDigestUpdate(ncc_digest_t* stream, cspan_t source)
	{
		DEBUG_ASSERT(stream);
		if (!stream)
		{
			return 0;
		}

		_ssize_guard_int(spanGetSizeC(source))

		if (stream->flags & NC_CRYPTO_DIGEST_FLAGS_HMAC)
		{
			return mbedtls_md_hmac_update(
				&stream->ctx,
				spanGetOffsetC(source, 0),
				spanGetSizeC(source)
			) == 0 ? CSTATUS_OK : CSTATUS_FAIL;
		}
		else
		{
			return mbedtls_md_update(
				&stream->ctx,
				spanGetOffsetC(source, 0),
				spanGetSizeC(source)
			) == 0 ? CSTATUS_OK : CSTATUS_FAIL;
		}	
	}

	cstatus_t ncCryptoDigestFinish(ncc_digest_t* stream, span_t output)
	{
		int result;

		DEBUG_ASSERT(stream);
		if (!stream)
		{
			return 0;
		}

		_ssize_guard_int(spanGetSize(output))

		if (stream->flags & NC_CRYPTO_DIGEST_FLAGS_HMAC)
		{
			result = mbedtls_md_hmac_finish(&stream->ctx, spanGetOffset(output, 0));
		}
		else
		{
			result = mbedtls_md_finish(&stream->ctx, spanGetOffset(output, 0));
		}

		return result == 0 ? CSTATUS_OK : CSTATUS_FAIL;
	}

#endif /* !_DIGSET_STREAM_INTERFACE */
