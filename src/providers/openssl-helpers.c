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


#include <openssl/crypto.h>
#include <openssl/evp.h>

#define OSSL_SHA256 "SHA2-256"
#define OSSL_HMAC "hmac"
#define ossl_evp_fetch_chacha20() EVP_CIPHER_fetch(NULL, "ChaCha20", NULL)


typedef enum {
	
	EvpStateTypeDigest,
	
	EvpStateTypeMac

} _evp_state_type;

struct ossl_evp_state {
	void* _context;
	void* _providerHandle;

	OSSL_PARAM params[2];

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

	}

	return (cstatus_t)(result != 0);
}

_IMPLSTB cstatus_t _osslEvpFinal(const struct ossl_evp_state* state, span_t out)
{
	int result;
	size_t hmacLen;
	unsigned int mdLen;

	DEBUG_ASSERT(state != NULL);

	result = 0;
	mdLen = hmacLen = ncSpanGetSize(out);

	switch (state->type)
	{
	case EvpStateTypeDigest:
		result = EVP_DigestFinal_ex(
			_osslEvpGetMdContext(state),
			ncSpanGetOffset(out, 0),
			&mdLen
		);
		
		return (cstatus_t)(result != 0 && mdLen == ncSpanGetSize(out));

	case EvpStateTypeMac:
		result = EVP_MAC_final(
			_osslEvpGetMacContext(state),
			ncSpanGetOffset(out, 0),
			&hmacLen,
			hmacLen
		);
		return (cstatus_t)(result != 0 && hmacLen == ncSpanGetSize(out));
	}

	/*
	* If the result is non-zero and the hash length is equal to the output
	* buffer size, return success, otherwise return failure.
	*/

	return CSTATUS_FAIL;
}

_IMPLSTB cstatus_t _osslEvpMacInit(const struct ossl_evp_state* state)
{
	int result;

	DEBUG_ASSERT(state != NULL);
	DEBUG_ASSERT(state->type == EvpStateTypeMac);
	DEBUG_ASSERT(ncSpanIsValidC(state->_prk));

	result = EVP_MAC_init(
		_osslEvpGetMacContext(state),
		ncSpanGetOffsetC(state->_prk, 0),
		ncSpanGetSizeC(state->_prk),
		state->params
	);

	return (cstatus_t)(result != 0);
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
				(EVP_MD_CTX*)state->_context,
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
