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

#include <openssl/sha.h>

#include "../../platform.h"
#include "../nc-util.h"

/*
*		EXPORT SUPPORTED FUNCTIONS AS MACROS
*/
#define _IMPL_CHACHA20_CRYPT				_mbed_chacha20_encrypt			
#define _IMPL_CRYPTO_SHA256_HMAC			_mbed_sha256_hmac
#define _IMPL_CRYPTO_SHA256_DIGEST			_ossl_sha256_digest	
#define _IMPL_CRYPTO_FIXED_TIME_COMPARE		_mbed_fixed_time_compare
#define _IMPL_CRYPTO_SHA256_HKDF_EXPAND		_mbed_sha256_hkdf_expand
#define _IMPL_CRYPTO_SHA256_HKDF_EXTRACT	_mbed_sha256_hkdf_extract

_IMPLSTB int _ossl_sha256_digest(const uint8_t* data, uint8_t* digest)
{
	
}


#endif	/*!OPENSSL_CRYPTO_LIB */