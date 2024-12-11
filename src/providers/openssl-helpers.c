/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: providers/openssl-helpers.c
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


#include <openssl/crypto.h>
#include <openssl/evp.h>

#define OSSL_SHA256 "SHA2-256"
#define OSSL_HMAC "hmac"
#define OSSL_CHACHA20 "ChaCha20"


typedef enum {
	
	EvpStateTypeInvalid,

	EvpStateTypeDigest,
	
	EvpStateTypeMac,

	EvpStateTypeCipher

} _evp_state_type;

struct ossl_evp_state {
	void* _context;
	void* _providerHandle;	

	_evp_state_type type;

	cspan_t _prk;
};


_IMPLSTB EVP_MAC_CTX* _osslEvpGetMacContext(const struct ossl_evp_state* state)
{
	DEBUG_ASSERT(state != NULL);
	DEBUG_ASSERT(state->type == EvpStateTypeMac);

	return (EVP_MAC_CTX*)state->_context;
}

_IMPLSTB EVP_MD_CTX* _osslEvpGetMdContext(const struct ossl_evp_state* state)
{
	DEBUG_ASSERT(state != NULL);
	DEBUG_ASSERT(state->type == EvpStateTypeDigest);

	return (EVP_MD_CTX*)state->_context;
}

_IMPLSTB EVP_CIPHER_CTX* _osslEvpGetCipherContext(const struct ossl_evp_state* state)
{
	DEBUG_ASSERT(state != NULL);
	DEBUG_ASSERT(state->type == EvpStateTypeCipher);

	return (EVP_CIPHER_CTX*)state->_context;
}

_IMPLSTB cspan_t _osslEvpGetPrk(const struct ossl_evp_state* state)
{
	DEBUG_ASSERT(state != NULL);

	return state->_prk;
}

_IMPLSTB void _osslEvpSetPrk(struct ossl_evp_state* state, cspan_t prk)
{
	DEBUG_ASSERT(state != NULL);

	state->_prk = prk;
}

_IMPLSTB cstatus_t _osslEvpUpdate(const struct ossl_evp_state* state, cspan_t data)
{
	int result;

	DEBUG_ASSERT(state != NULL);
	DEBUG_ASSERT(state->_context != NULL);

	result = 0;

	switch (state->type)
	{
	case EvpStateTypeDigest:
		result = EVP_DigestUpdate(
			_osslEvpGetMdContext(state),
			ncSpanGetOffsetC(data, 0),
			ncSpanGetSizeC(data)
		);
		break;

	case EvpStateTypeMac:
		result = EVP_MAC_update(
			_osslEvpGetMacContext(state),
			ncSpanGetOffsetC(data, 0),
			ncSpanGetSizeC(data)
		);
		break;
		/* Cipher is not supported by this api */
	default:
		DEBUG_ASSERT2(0, "Called update on an invalid state type");
		break;
	}

	return (cstatus_t)(result != 0);
}

_IMPLSTB cstatus_t _osslEvpCipherUpdate(
	const struct ossl_evp_state* state, 
	cspan_t input, 
	span_t output, 
	int* bytesConsumed
)
{
	int result;

	DEBUG_ASSERT(state != NULL);
	DEBUG_ASSERT(state->_context != NULL);
	DEBUG_ASSERT(state->type == EvpStateTypeCipher);

	result = EVP_EncryptUpdate(
		_osslEvpGetCipherContext(state),
		ncSpanGetOffset(output, 0),
		bytesConsumed,
		ncSpanGetOffsetC(input, 0),
		ncSpanGetSizeC(input)
	);

	return (cstatus_t)(result != 0);
}

_IMPLSTB cstatus_t __digestFinal(const struct ossl_evp_state* state, span_t out)
{
	int result;
	unsigned int mdOut;

	DEBUG_ASSERT(state != NULL);
	DEBUG_ASSERT(state->type == EvpStateTypeDigest);

	mdOut = ncSpanGetSize(out);

	/* If the output span is empty, nothing to do */
	if (mdOut == 0)
	{
		return CSTATUS_OK;
	}

	result = EVP_DigestFinal_ex(
		_osslEvpGetMdContext(state),
		ncSpanGetOffset(out, 0),
		&mdOut
	);

	return (cstatus_t)(result != 0 && mdOut == ncSpanGetSize(out));
}

_IMPLSTB cstatus_t __macFinal(const struct ossl_evp_state* state, span_t out)
{
	int result;
	size_t macOut;

	DEBUG_ASSERT(state != NULL);
	DEBUG_ASSERT(state->type == EvpStateTypeMac);

	macOut = ncSpanGetSize(out);

	/* If the output span is empty, nothing to do */
	if (macOut == 0)
	{
		return CSTATUS_OK;
	}

	result = EVP_MAC_final(
		_osslEvpGetMacContext(state),
		ncSpanGetOffset(out, 0),
		&macOut,
		macOut
	);

	return (cstatus_t)(result != 0 && macOut == ncSpanGetSize(out));
}

_IMPLSTB cstatus_t __cipherFinal(const struct ossl_evp_state* state, span_t out)
{
	int result, cipherOut;

	DEBUG_ASSERT(state != NULL);
	DEBUG_ASSERT(state->type == EvpStateTypeCipher);
	
	/* guard small integer overflow */
	if (ncSpanGetSize(out) > INT_MAX)
	{
		return CSTATUS_FAIL;
	}

	cipherOut = (int)ncSpanGetSize(out);

	/* If the output span is empty, nothing to do */
	if (cipherOut == 0)
	{
		return CSTATUS_OK;
	}

	result = EVP_CipherFinal_ex(
		_osslEvpGetCipherContext(state),
		ncSpanGetOffset(out, 0),
		&cipherOut
	);

	return (cstatus_t)(result != 0 && cipherOut >= 0 && (uint32_t)cipherOut == ncSpanGetSize(out));
}

static cstatus_t _osslEvpFinal(const struct ossl_evp_state* state, span_t out)
{
	DEBUG_ASSERT(state != NULL);

	switch (state->type)
	{
	case EvpStateTypeDigest:
		return __digestFinal(state, out);

	case EvpStateTypeMac:
		return __macFinal(state, out);

	case EvpStateTypeCipher:
		return __cipherFinal(state, out);

	default:
		break;
	}

	/*
	* If the result is non-zero and the hash length is equal to the output
	* buffer size, return success, otherwise return failure.
	*/

	return CSTATUS_FAIL;
}

_IMPLSTB cstatus_t _osslEvpMacInit(const struct ossl_evp_state* state, const OSSL_PARAM* params)
{
	int result;

	DEBUG_ASSERT(state != NULL);
	DEBUG_ASSERT(state->type == EvpStateTypeMac);
	DEBUG_ASSERT(ncSpanIsValidC(state->_prk));

	result = EVP_MAC_init(
		_osslEvpGetMacContext(state),
		ncSpanGetOffsetC(state->_prk, 0),
		ncSpanGetSizeC(state->_prk),
		params
	);

	return (cstatus_t)(result != 0);
}

_IMPLSTB cstatus_t _osslEvpCipherInit(const struct ossl_evp_state* state, cspan_t key, cspan_t iv)
{
	int osslResult;
	const EVP_CIPHER* cipher;

	DEBUG_ASSERT(state != NULL);

	cipher = (const EVP_CIPHER*)state->_providerHandle;

	/*
	* Sanity check on key and IV sizes for the created
	* cipher
	*/
	DEBUG_ASSERT((uint32_t)EVP_CIPHER_get_key_length(cipher) == ncSpanGetSizeC(key));
	DEBUG_ASSERT((uint32_t)EVP_CIPHER_iv_length(cipher) == ncSpanGetSizeC(iv));

	osslResult = EVP_EncryptInit_ex2(
		_osslEvpGetCipherContext(state),
		cipher,
		ncSpanGetOffsetC(key, 0),
		ncSpanGetOffsetC(iv, 0),
		NULL
	);

	return (cstatus_t)(osslResult != 0);
}

_IMPLSTB void _osslEvpFree(struct ossl_evp_state* state)
{
	DEBUG_ASSERT(state != NULL);

	switch (state->type)
	{
	case EvpStateTypeDigest:
		if (state->_context) EVP_MD_CTX_free(state->_context);
		if (state->_providerHandle) EVP_MD_free(state->_providerHandle);
		break;
	case EvpStateTypeMac:
		if (state->_context) EVP_MAC_CTX_free(state->_context);
		if (state->_providerHandle) EVP_MAC_free(state->_providerHandle);
		break;
	case EvpStateTypeCipher:
		if (state->_context) EVP_CIPHER_CTX_free(state->_context);
		if (state->_providerHandle) EVP_CIPHER_free(state->_providerHandle);
		break;
	default:
		break;
	}
}

_IMPLSTB cstatus_t _osslEvpInit(
	struct ossl_evp_state* state,
	_evp_state_type type,
	const char* providerName
)
{
	DEBUG_ASSERT(state != NULL);
	DEBUG_ASSERT(providerName != NULL);

	state->type = type;
	state->_context = NULL;
	state->_providerHandle = NULL;

	switch (type)
	{
	case EvpStateTypeDigest:
		state->_providerHandle = EVP_MD_fetch(NULL, providerName, NULL);
		state->_context = EVP_MD_CTX_new();		
		break;
	case EvpStateTypeMac:

		state->_providerHandle = EVP_MAC_fetch(NULL, providerName, NULL);

		if (state->_providerHandle)
		{
			state->_context = EVP_MAC_CTX_new((EVP_MAC*)(state->_providerHandle));
		}

		break;
	case EvpStateTypeCipher:
		state->_providerHandle = EVP_CIPHER_fetch(NULL, providerName, NULL);
		state->_context = EVP_CIPHER_CTX_new();
		break;

	default:
		return CSTATUS_FAIL;
	}

	/*
	* Ensure allocations succeded, otherwise free the context
	* and return a failure status.
	*/
	if (state->_providerHandle == NULL || state->_context == NULL)
	{		
		return CSTATUS_FAIL;
	}

	/*
	* If the type is a digest, initialize the digest context
	*/
	if (type == EvpStateTypeDigest)
	{
		if (
			!EVP_DigestInit_ex(
				_osslEvpGetMdContext(state),
				(EVP_MD*)state->_providerHandle,
				NULL
			)
		)
		{
			return CSTATUS_FAIL;
		}
	}

	return CSTATUS_OK;
}
