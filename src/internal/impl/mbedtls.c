/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: mbedtls.c
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

#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/sha256.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/constant_time.h>

#include "../../platform.h"
#include "../nc-util.h"

/*
*		EXPORT SUPPORTED FUNCTION OVERRIDES
*/	

_IMPLSTB const mbedtls_md_info_t* _mbed_sha256_alg(void)
{
	const mbedtls_md_info_t* info;
	/* Get sha256 md info for hdkf operations */
	info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	DEBUG_ASSERT2(info != NULL, "Expected SHA256 md info pointer to be valid")
	return info;
}

#ifndef _IMPL_CHACHA20_CRYPT
	
	/* Export chacha20 computation */
	#define _IMPL_CHACHA20_CRYPT _mbed_chacha20_encrypt	

	_IMPLSTB int _mbed_chacha20_encrypt(
		const uint8_t* key,
		const uint8_t* nonce,
		const uint8_t* input,
		uint8_t* output,
		size_t dataLen
	)
	{
		/* Counter always starts at 0 */
		return mbedtls_chacha20_crypt(key, nonce, 0x00u, dataLen, input, output);
	}

#endif

/* Export sha256 if not already defined */
#ifndef _IMPL_CRYPTO_SHA256_DIGEST	
	
	#define _IMPL_CRYPTO_SHA256_DIGEST			_mbed_sha256_digest	

	_IMPLSTB CStatus _mbed_sha256_digest(const uint8_t* data, size_t dataSize,uint8_t* digestOut32)
	{
		return mbedtls_sha256(data, dataSize, digestOut32, 0);
	}

#endif

/* Export Sha256 hmac if not already defined by other libs */
#ifndef _IMPL_CRYPTO_SHA256_HMAC

	#define _IMPL_CRYPTO_SHA256_HMAC			_mbed_sha256_hmac

	_IMPLSTB CStatus _mbed_sha256_hmac(
		const uint8_t* key, size_t keyLen,
		const uint8_t* data, size_t dataLen,
		void* hmacOut32
	)
	{
		return mbedtls_md_hmac(
			_mbed_sha256_alg(),
			key, keyLen,
			data, dataLen,
			hmacOut32
		);
	}
#endif

/* Export hkdf expand if not already defined */
#ifndef _IMPL_CRYPTO_SHA256_HKDF_EXPAND

	#define _IMPL_CRYPTO_SHA256_HKDF_EXPAND		_mbed_sha256_hkdf_expand

	_IMPLSTB int _mbed_sha256_hkdf_expand(
		const uint8_t* prk, size_t prkLen,
		const uint8_t* info, size_t infoLen,
		void* okm, size_t okmLen
	)
	{
		return mbedtls_hkdf_expand(
			_mbed_sha256_alg(),
			prk, prkLen,
			info, infoLen,
			okm, okmLen
		);
	}

#endif

/* Export hkdf extract if not already defined */
#ifndef _IMPL_CRYPTO_SHA256_HKDF_EXTRACT

	#define _IMPL_CRYPTO_SHA256_HKDF_EXTRACT		_mbed_sha256_hkdf_extract

	_IMPLSTB int _mbed_sha256_hkdf_extract(
		const uint8_t* salt, size_t saltLen,
		const uint8_t* ikm, size_t ikmLen,
		void* prk
	)
	{
		return mbedtls_hkdf_extract(
			_mbed_sha256_alg(),
			salt, saltLen,
			ikm, ikmLen,
			prk
		);
	}
#endif

/* Export fixed-time compare if not already defined */
#ifndef _IMPL_CRYPTO_FIXED_TIME_COMPARE

	#define _IMPL_CRYPTO_FIXED_TIME_COMPARE		_mbed_fixed_time_compare

	/* fixed-time memcmp */
	_IMPLSTB int _mbed_fixed_time_compare(const uint8_t* a, const uint8_t* b, size_t size)
	{
		return mbedtls_ct_memcmp(a, b, size);
	}
#endif

#endif