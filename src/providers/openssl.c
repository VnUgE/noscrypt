/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: impl/openssl.c
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


/* Setup openssl */
#ifdef OPENSSL_CRYPTO_LIB

#include <openssl/crypto.h>

#define _OSSL_FAIL(x) if(!(x)) return CSTATUS_FAIL;

#ifndef _IMPL_SECURE_ZERO_MEMSET

	#define _IMPL_SECURE_ZERO_MEMSET			_ossl_secure_zero_memset

	_IMPLSTB void _ossl_secure_zero_memset(void* ptr, size_t size)
	{
		_overflow_check(size)

		OPENSSL_cleanse(ptr, size);
	}
#endif

#ifndef _IMPL_CRYPTO_FIXED_TIME_COMPARE

	#define _IMPL_CRYPTO_FIXED_TIME_COMPARE		_ossl_fixed_time_compare

	_IMPLSTB uint32_t _ossl_fixed_time_compare(const uint8_t* a, const uint8_t* b, uint32_t size)
	{
		int result;

		/* Size checks are required for platforms that have integer sizes under 32bit */
		_overflow_check(size)

		result = CRYPTO_memcmp(a, b, size);

		return (uint32_t)result;
	}

#endif /* _IMPL_CRYPTO_FIXED_TIME_COMPARE */


#ifndef _IMPL_CRYPTO_SHA256_DIGEST	

	#include <openssl/sha.h>

	#define _IMPL_CRYPTO_SHA256_DIGEST			_ossl_sha256_digest	

	_IMPLSTB cstatus_t _ossl_sha256_digest(const cspan_t* data, sha256_t digestOut32)
	{
		_overflow_check(data->size)

		_OSSL_FAIL(SHA256(data->data, data->size, digestOut32))

		return CSTATUS_OK;
	}

#endif

#ifndef _IMPL_CRYPTO_SHA256_HMAC

	#include <openssl/hmac.h>

	/* Export function */
	#define _IMPL_CRYPTO_SHA256_HMAC			_ossl_hmac_sha256	
	
	_IMPLSTB cstatus_t _ossl_hmac_sha256(const cspan_t* key, const cspan_t* data, sha256_t hmacOut32)
	{
		unsigned int hmacLen;

		_overflow_check(key->size)
		_overflow_check(data->size)

		hmacLen = sizeof(sha256_t);

		_OSSL_FAIL(
			HMAC(
				EVP_sha256(),
				key->data,
				key->size,
				data->data,
				data->size,
				hmacOut32,
				&hmacLen
			)
		)
		
		/* digest length should match the actual digest size */
		DEBUG_ASSERT(hmacLen == sizeof(sha256_t))

		return CSTATUS_OK;
	}

#endif /* !_IMPL_CRYPTO_SHA256_HMAC */

#ifndef _IMPL_CRYPTO_SHA256_HKDF_EXPAND
	
	#include <openssl/hmac.h>

	#define _IMPL_CRYPTO_SHA256_HKDF_EXPAND		_ossl_sha256_hkdf_expand

	cstatus_t _ossl_hkdf_update(void* ctx, const cspan_t* data)
	{
		DEBUG_ASSERT(ctx != NULL)

		_overflow_check(data->size)

		_OSSL_FAIL(EVP_DigestUpdate((EVP_MD_CTX*)ctx, data->data, data->size))
		
		return CSTATUS_OK;
	}

	cstatus_t _ossl_hkdf_finish(void* ctx, sha256_t hmacOut32)
	{
		unsigned int hmacSize;

		DEBUG_ASSERT(ctx != NULL)

		hmacSize = sizeof(sha256_t);

		_OSSL_FAIL(EVP_DigestFinal_ex((EVP_MD_CTX*)ctx, hmacOut32, &hmacSize))

		/* When configured for sha256, should always be the same size in/out */
		DEBUG_ASSERT(hmacSize == sizeof(sha256_t))
		
		return CSTATUS_OK;
	}

	_IMPLSTB cstatus_t _ossl_sha256_hkdf_expand(const cspan_t* prk, const cspan_t* info, span_t* okm)
	{
		EVP_MD_CTX* ctx;
		cstatus_t result;
		struct nc_hkdf_fn_cb_struct handler;

		result = CSTATUS_FAIL;
	
		/*
		* NOTE! Hmac reusable flag must be set to allow for multiple
		* calls to the finish function without losing the context.
		*/

		if ((ctx = EVP_MD_CTX_create()) == NULL)
		{
			return CSTATUS_FAIL;
		}

		if (!EVP_DigestInit_ex2(ctx, EVP_sha256(), NULL))
		{
			goto Cleanup;
		}

		if (!EVP_DigestUpdate(ctx, prk->data, prk->size)) 
		{
			goto Cleanup;
		}
		
		handler.update = _ossl_hkdf_update;
		handler.finish = _ossl_hkdf_finish;

		result = hkdfExpandProcess(&handler, ctx, info, okm);

	Cleanup:

		EVP_MD_CTX_destroy(ctx);

		return result;
	}

#endif /* !_IMPL_CRYPTO_SHA256_HKDF_EXPAND */

#ifndef _IMPL_CHACHA20_CRYPT

    #include <openssl/evp.h>

	#define _IMPL_CHACHA20_CRYPT _ossl_chacha20_crypt

	_IMPLSTB cstatus_t _ossl_chacha20_crypt(
		const uint8_t* key,
		const uint8_t* nonce,
		const uint8_t* input,
		uint8_t* output,
		uint32_t dataLen
	)
	{
		cstatus_t result;
		EVP_CIPHER_CTX* ctx;

		result = CSTATUS_FAIL;

		if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
		{
			return CSTATUS_FAIL;
		}

		if (!EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce))
		{
			goto Cleanup;
		}

		if (!EVP_EncryptUpdate(ctx, output, (int*)&dataLen, input, dataLen))
		{
			goto Cleanup;
		}

		result = CSTATUS_OK;

	Cleanup:

		EVP_CIPHER_CTX_free(ctx);

		return result;
	}

#endif

#endif	/*!OPENSSL_CRYPTO_LIB */