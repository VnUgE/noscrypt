/*
* Copyright (c) 2026 Vaughn Nugent
*
* Package: noscrypt
* File: providers/openssl.c
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
* Since openssl depends on the variable size 
* size_t type but spans use fixed size uint32_t
* we need to ensure that the size of size_t is
* at least 32 bits. 
* 
* This means this implementation requires 32bit 
* or larger size_t types to use openssl.
*/
#if SIZE_MAX < UINT32_MAX
	#error "Openssl backend requires at least 32bit system word sizes"
#endif

#define OSSL_SHA256 "SHA2-256"
#define OSSL_HMAC "hmac"
#define OSSL_CHACHA20 "ChaCha20"

#include "openssl-helpers.c"

#ifndef _IMPL_SECURE_ZERO_MEMSET

	#define _IMPL_SECURE_ZERO_MEMSET			_ossl_secure_zero_memset

	_IMPLSTB void _ossl_secure_zero_memset(void* ptr, size_t size)
	{
		OPENSSL_cleanse(ptr, size);
	}
#endif

#ifndef _IMPL_CRYPTO_FIXED_TIME_COMPARE

	#define _IMPL_CRYPTO_FIXED_TIME_COMPARE		_ossl_fixed_time_compare

	_IMPLSTB uint32_t _ossl_fixed_time_compare(const uint8_t* a, const uint8_t* b, uint32_t size)
	{
		return (uint32_t)CRYPTO_memcmp(a, b, size);
	}

#endif /* _IMPL_CRYPTO_FIXED_TIME_COMPARE */

#ifndef _IMPL_CHACHA20_CRYPT

	#define _IMPL_CHACHA20_CRYPT _ossl_chacha20_crypt
	
	_IMPLSTB cstatus_t _ossl_chacha20_crypt(
		cspan_t key,
		cspan_t nonce,
		cspan_t input,
		span_t output
	)
	{
		cstatus_t result;
		struct ossl_evp_state state;
		uint8_t chaChaNonce[NC_CRYPTO_CHACHA_NONCE_SIZE + 4];
		cspan_t nonceSpan;
		int bytesWritten;

		result = CSTATUS_FAIL;
		bytesWritten = 0;

		spanInitC(&nonceSpan, chaChaNonce, sizeof(chaChaNonce));

		/* Ensure output buffer is at least large enough to store input data */
		if (spanGetSize(output) < spanGetSizeC(input))
		{
			return CSTATUS_FAIL;
		}

		/*
		* Alloc and init the cipher state for ChaCha20 in 
		* cipher mode
		*/
		if (!_osslEvpInit(&state, EvpStateTypeCipher, OSSL_CHACHA20))
		{
			goto Cleanup;
		}

		DEBUG_ASSERT2(spanGetSizeC(key) == NC_CRYPTO_CHACHA_KEY_SIZE, "ChaCha key buffer size is not correct");

		/*
		* RFC 7539 ChaCha20 requires a 16 byte initialization vector. A 
		* counter value is prepended to the nonce to make up the 16 byte 
		* size.
		*
		* The counter bytes are always set to 0 for the nonce.
		*/

		ncCryptoSecureZero(chaChaNonce, sizeof(chaChaNonce));
		spanReadC(nonce, chaChaNonce + 4, NC_CRYPTO_CHACHA_NONCE_SIZE);

		if (!_osslEvpCipherInit(&state, key, nonceSpan))
		{
			goto Cleanup;
		}

		if (!_osslEvpCipherUpdate(&state, input, output, &bytesWritten))
		{
			goto Cleanup;
		}
		
		/* int must be 32-bit or smaller so bytesWritten casts safely to uint32 */
		STATIC_ASSERT(sizeof(int) <= sizeof(int32_t), "int must be <= 32 bits for safe cast to uint32_t")

		if (bytesWritten < 0)
		{
			goto Cleanup;
		}

		DEBUG_ASSERT((uint32_t)bytesWritten <= spanGetSizeC(input))

		/* shift output span by consumed data amount */
		output = spanSlice(
		    output,
			(uint32_t)bytesWritten,
			spanGetSizeC(input) - (uint32_t)bytesWritten
		);

		if (!_osslEvpFinal(&state, output))
		{
			goto Cleanup;
		}
	
		result = CSTATUS_OK;

	Cleanup:
		
		_osslEvpFree(&state);

		return result;
	}

#endif

#ifndef _DIGSET_STREAM_INTERFACE

	#define _DIGSET_STREAM_INTERFACE "openssl"

	void ncCryptoDigestClose(ncc_digest_t* stream)
	{
		DEBUG_ASSERT(stream);
		if (!stream)
		{
			return;
		}

		if (stream->flags & NC_CRYPTO_DIGEST_FLAGS_HMAC)
		{
			if (stream->ctx._context) EVP_MAC_CTX_free(stream->ctx._context);
			if (stream->ctx._providerHandle) EVP_MAC_free(stream->ctx._providerHandle);
		}
		else
		{
			if (stream->ctx._context) EVP_MD_CTX_free(stream->ctx._context);
			if (stream->ctx._providerHandle) EVP_MD_free(stream->ctx._providerHandle);
		}

		ncCryptoSecureZero(stream, sizeof(ncc_digest_t));
	}

	cstatus_t ncCryptoDigestCreate(ncc_digest_t* stream, uint32_t flags)
	{
		const char* digestName;

		DEBUG_ASSERT(stream);
		if (!stream)
		{
			return CSTATUS_FAIL;
		}

		switch (flags & NC_CRYPTO_DIGEST_TYPE_MASK)
		{
		case NC_CRYPTO_DIGEST_TYPE_SHA256:
			digestName = OSSL_SHA256;
			break;

		default:
			return CSTATUS_FAIL;
		}

		_IMPL_SECURE_ZERO_MEMSET(stream, sizeof(ncc_digest_t));

		if ((flags & NC_CRYPTO_DIGEST_FLAGS_HMAC) > 0)
		{
			stream->ctx._providerHandle = EVP_MAC_fetch(NULL, OSSL_HMAC, NULL);
			if (!stream->ctx._providerHandle)
			{
				goto Fail;
			}

			stream->ctx._context = EVP_MAC_CTX_new((EVP_MAC*)stream->ctx._providerHandle);
			if (!stream->ctx._context)
			{
				goto Fail;
			}
		}
		else
		{
			stream->ctx._providerHandle = EVP_MD_fetch(NULL, digestName, NULL);
			if (!stream->ctx._providerHandle)
			{
				goto Fail;
			}

			stream->ctx._context = EVP_MD_CTX_new();
			if (!stream->ctx._context)
			{
				goto Fail;
			}
		}

		DEBUG_ASSERT(stream->ctx._providerHandle);
		DEBUG_ASSERT(stream->ctx._context);

		stream->flags = (flags | NC_CRYPTO_DIGEST_FLAGS_READY);

		return CSTATUS_OK;

	Fail:

		ncCryptoDigestClose(stream);
		return CSTATUS_FAIL;
	}

	cstatus_t ncCryptoDigestInit(ncc_digest_t* stream, cspan_t hmacKey)
	{
		DEBUG_ASSERT(stream);
		if (!stream)
		{
			return CSTATUS_FAIL;
		}

		if ((stream->flags & NC_CRYPTO_DIGEST_FLAGS_HMAC) > 0)
		{
			/* must remain in scope until Init() returns */
			OSSL_PARAM params[2];
			uint8_t dummyKey[4];
			const uint8_t* keyPtr;

			/* sets all entries to empty() */
			_IMPL_SECURE_ZERO_MEMSET(params, sizeof(params));

			params[0] = OSSL_PARAM_construct_utf8_string("digest", OSSL_SHA256, 0);
			
			/*
			* NOTE: Openssl has an outstanding issue with handling null key pointers for emtpy keys.
			* it returns false always. To work around this, HMAC rfcs require using zero keys, in that
			* the zero-key of any size does not change the output in any way. Keys are guaranteed to be
			* padded to their correct size by the RFC so we just pass an arbitrary value **zeroed** key
			* 
			* https://github.com/openssl/openssl/issues/31068
			*/			
			
			if (spanGetSizeC(hmacKey) > 0) 
			{
				keyPtr = spanGetOffsetC(hmacKey, 0);
			}
			else
			{
				_IMPL_SECURE_ZERO_MEMSET(dummyKey, sizeof(dummyKey));

				keyPtr = dummyKey;
			}

			if (!EVP_MAC_init((EVP_MAC_CTX*)stream->ctx._context, keyPtr, spanGetSizeC(hmacKey), params))
			{
				return CSTATUS_FAIL;
			}
		}
		else
		{
			if (!EVP_DigestInit_ex2(
				(EVP_MD_CTX*)stream->ctx._context,
				(EVP_MD*)stream->ctx._providerHandle,
				NULL
			))
			{
				return CSTATUS_FAIL;
			}
		}

		return CSTATUS_OK;
	}

	cstatus_t ncCryptoDigestUpdate(ncc_digest_t* stream, cspan_t source)
	{
		int result;

		DEBUG_ASSERT(stream);
		if (!stream)
		{
			return CSTATUS_FAIL;
		}

		if (stream->flags & NC_CRYPTO_DIGEST_FLAGS_HMAC)
		{
			result = EVP_MAC_update(
				(EVP_MAC_CTX*)stream->ctx._context,
				spanGetOffsetC(source, 0),
				spanGetSizeC(source)
			);
		}
		else
		{
			result = EVP_DigestUpdate(
				(EVP_MD_CTX*)stream->ctx._context,
				spanGetOffsetC(source, 0),
				spanGetSizeC(source)
			);
		}

		return (cstatus_t)(result != 0);
	}
	
	cstatus_t ncCryptoDigestFinish(ncc_digest_t* stream, span_t output)
	{
		int result;
		size_t macOutLen;
		unsigned int digestOutLen;

		DEBUG_ASSERT(stream);
		if (!stream)
		{
			return CSTATUS_FAIL;
		}

		if (stream->flags & NC_CRYPTO_DIGEST_FLAGS_HMAC)
		{
			macOutLen = (size_t)spanGetSize(output);

			result = EVP_MAC_final(
				(EVP_MAC_CTX*)stream->ctx._context,
				spanGetOffset(output, 0),
				&macOutLen,
				macOutLen
			);
		}
		else
		{
			digestOutLen = (unsigned int)spanGetSize(output);

			result = EVP_DigestFinal_ex(
				(EVP_MD_CTX*)stream->ctx._context,
				spanGetOffset(output, 0),
				&digestOutLen
			);
		}

		return (cstatus_t)(result != 0);
	}
	

#endif /* !_DIGSET_STREAM_INTERFACE */
