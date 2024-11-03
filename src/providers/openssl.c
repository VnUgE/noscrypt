/*
* Copyright (c) 2024 Vaughn Nugent
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


/* Setup openssl */
#ifdef OPENSSL_CRYPTO_LIB

#include "openssl-helpers.c"

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

	#define _IMPL_CRYPTO_SHA256_DIGEST			_ossl_sha256_digest	

	_IMPLSTB cstatus_t _ossl_sha256_digest(cspan_t data, sha256_t digestOut32)
	{
		cstatus_t result;
		span_t digestSpan;
		struct ossl_evp_state evpState;		

		DEBUG_ASSERT(digestOut32 != NULL);
		DEBUG_ASSERT(ncSpanIsValidC(data));

		result = CSTATUS_FAIL;

		_overflow_check(data.size);

		ncSpanInit(&digestSpan, digestOut32, sizeof(sha256_t));

		/*
		* Allocate and initalize the context
		*/
		if (!_osslEvpInit(&evpState, EvpStateTypeDigest, OSSL_SHA256))
		{
			goto Cleanup;
		}

		if (!_osslEvpUpdate(&evpState, data))
		{
			goto Cleanup;
		}

		if (!_osslEvpFinal(&evpState, digestSpan))
		{
			goto Cleanup;
		}

		result = CSTATUS_OK;

	Cleanup:

		_osslEvpFree(&evpState);

		return result;
	}

#endif

#ifndef _IMPL_CRYPTO_SHA256_HMAC

	/* Export function */
	#define _IMPL_CRYPTO_SHA256_HMAC			_ossl_hmac_sha256	
	
	_IMPLSTB cstatus_t _ossl_hmac_sha256(cspan_t key, cspan_t data, sha256_t hmacOut32)
	{
		cstatus_t result;
		span_t digestSpan;	
		OSSL_PARAM params[2];
		struct ossl_evp_state evpState;

		result = CSTATUS_FAIL;

		_overflow_check(key.size)
		_overflow_check(data.size)

		ncSpanInit(&digestSpan, hmacOut32, sizeof(sha256_t));

		/*
		* Allocate and initalize the context
		*/
		if (!_osslEvpInit(&evpState, EvpStateTypeMac, OSSL_HMAC))
		{
			goto Cleanup;
		}

		/*
		* To use HMAC the digest parameters must be set
		* before the context can be initialized
		*/

		params[0] = OSSL_PARAM_construct_utf8_string("digest", "sha256", 0);
		params[1] = OSSL_PARAM_construct_end();

		/*
		* PRK Data must be assigned before the hmac 
		* can be initialized
		*/

		_osslEvpSetPrk(&evpState, key);
	
		if (!_osslEvpMacInit(&evpState, params))
		{
			goto Cleanup;
		}

		if (!_osslEvpUpdate(&evpState, data))
		{
			goto Cleanup;
		}

		if (!_osslEvpFinal(&evpState, digestSpan))
		{
			goto Cleanup;
		}
		
		result = CSTATUS_OK;

	Cleanup:

		_osslEvpFree(&evpState);

		return result;

	}

#endif /* !_IMPL_CRYPTO_SHA256_HMAC */

#ifndef _IMPL_CRYPTO_SHA256_HKDF_EXPAND

	#define _IMPL_CRYPTO_SHA256_HKDF_EXPAND		_ossl_sha256_hkdf_expand

	struct _hkdf_state {
		OSSL_PARAM params[2];
		struct ossl_evp_state evpState;
	};

	static cstatus_t _ossl_hkdf_update(void* ctx, cspan_t data)
	{
		const struct _hkdf_state* state;

		DEBUG_ASSERT(ctx != NULL);
		_overflow_check(data.size);

		state = (const struct _hkdf_state*)ctx;

		return _osslEvpUpdate(
			&state->evpState, 
			data
		);
	}

	static cstatus_t _ossl_hkdf_finish(void* ctx, sha256_t hmacOut32)
	{
		span_t hmacSpan;
		const struct _hkdf_state* state;

		DEBUG_ASSERT(ctx != NULL);
		DEBUG_ASSERT(hmacOut32 != NULL);

		state = (const struct _hkdf_state*)ctx;
		ncSpanInit(&hmacSpan, hmacOut32, sizeof(sha256_t));

		if (!_osslEvpFinal(&state->evpState, hmacSpan))
		{
			return CSTATUS_FAIL;
		}

		/* 
		* Context must be re-initalized after finalize
		* See lifecycle https://docs.openssl.org/3.0/man7/life_cycle-mac/#copyright
		*/

		return _osslEvpMacInit(&state->evpState, state->params);
	}
	

	_IMPLSTB cstatus_t _ossl_sha256_hkdf_expand(cspan_t prk, cspan_t info, span_t okm)
	{
		cstatus_t result;
		struct _hkdf_state state;
		struct nc_hkdf_fn_cb_struct handler;		

		result = CSTATUS_FAIL;

		handler.update = _ossl_hkdf_update;
		handler.finish = _ossl_hkdf_finish;
	
		_overflow_check(prk.size);
		_overflow_check(info.size);
		_overflow_check(okm.size);

		/*
		* PRK Must be set before any call to MacInit
		*
		* Params must also be set for sha256 digest for mac
		*/
		_osslEvpSetPrk(&state.evpState, prk);

		/*
		* Silly openssl stuff. Enable hmac with sha256 using the system default
		* security provider. The one-shot flag must also be disabled (0) because
		* we need to call update multiple times.
		*/

		state.params[0] = OSSL_PARAM_construct_utf8_string("digest", "sha256", 0);
		state.params[1] = OSSL_PARAM_construct_end();

		if (!_osslEvpInit(&state.evpState, EvpStateTypeMac, OSSL_HMAC))
		{
			goto Cleanup;
		}

		if (_osslEvpMacInit(&state.evpState, state.params) != CSTATUS_OK)
		{
			goto Cleanup;
		}

		/* Sanity check mac size */
		DEBUG_ASSERT(EVP_MAC_CTX_get_mac_size(_osslEvpGetMacContext(&state.evpState)) == sizeof(sha256_t));

		/* Pass to the library  */
		result = hkdfExpandProcess(&handler, &state, info, okm);

	Cleanup:

		_osslEvpFree(&state.evpState);

		return result;
	}

#endif /* !_IMPL_CRYPTO_SHA256_HKDF_EXPAND */

#ifndef _IMPL_CHACHA20_CRYPT

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
		struct ossl_evp_state state;
		uint8_t chaChaIv[CHACHA_NONCE_SIZE + 4];
		cspan_t keySpan, nonceSpan, inputSpan;
		span_t outputSpan;
		int bytesWritten;

		result = CSTATUS_FAIL;
		bytesWritten = 0;

		/*
		* Alloc and init the cipher state for ChaCha20 in 
		* cipher mode
		*/
		if (!_osslEvpInit(&state, EvpStateTypeCipher, OSSL_CHACHA20))
		{
			goto Cleanup;
		}

		/*
		* RFC 7539 ChaCha20 requires a 16 byte initialization vector. A 
		* counter value is preprended to the nonce to make up the 16 byte 
		* size.
		*
		* The counter is always set to 0 for the nonce.
		*/

		ncCryptoSecureZero(chaChaIv, sizeof(chaChaIv));
		MEMMOV(chaChaIv + 4, nonce, CHACHA_NONCE_SIZE);

		ncSpanInitC(&keySpan, key, CHACHA_KEY_SIZE);
		ncSpanInitC(&nonceSpan, chaChaIv, sizeof(chaChaIv));
		ncSpanInitC(&inputSpan, input, dataLen);
		ncSpanInit(&outputSpan, output, dataLen);

		if (!_osslEvpCipherInit(&state, keySpan, nonceSpan))
		{
			goto Cleanup;
		}

		if (!_osslEvpCipherUpdate(&state, inputSpan, outputSpan, &bytesWritten))
		{
			goto Cleanup;
		}
		
		/*
		* Possible static asser that int size must be 32bit or smaller
		*/
		if (bytesWritten < 0 || bytesWritten > INT32_MAX)
		{
			goto Cleanup;
		}

		DEBUG_ASSERT((uint32_t)bytesWritten <= dataLen)

		/* shift output span by consumed data amount */
		outputSpan = ncSpanSlice(
			outputSpan, 
			(uint32_t)bytesWritten,
			dataLen - (uint32_t)bytesWritten
		);

		if (!_osslEvpFinal(&state, outputSpan))
		{
			goto Cleanup;
		}
	
		result = CSTATUS_OK;

	Cleanup:
		
		_osslEvpFree(&state);

		return result;
	}

#endif

#endif	/*!OPENSSL_CRYPTO_LIB */