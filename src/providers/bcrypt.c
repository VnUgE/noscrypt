/*
* Copyright (c) 2026 Vaughn Nugent
*
* Package: noscrypt
* File: providers/bcrypt.c
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
*	This file provides as many fallback implementations on Windows platforms
*	as possible using the bcrypt library. This file should be included behind
*	other library implementations, as it is a fallback.
*/


#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <bcrypt.h>

#ifndef _IMPL_SECURE_ZERO_MEMSET
	/*
	* On Windows, we can use SecureZeroMemory
	* as platform zeroing function.
	*
	* NOTE:
	* SecureZeroMemory2 uses volatile function argument
	* pointers, which is a contested method of compiler
	* optimization prevention. GNU seems to oppose this method
	*
	* https://learn.microsoft.com/en-us/windows/win32/memory/winbase-securezeromemory2
	*/
	#define _IMPL_SECURE_ZERO_MEMSET SecureZeroMemory
#endif /* !_IMPL_SECURE_ZERO_MEMSET */

/*
* Export the ncCrypto digest interface function overrides for bcrypt
* 
* This interface uses the bcrypt CNG algorithm pseudo-handles for 
* reusing OS handles instead of opening/closing provider handles.
* 
* https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-pseudo-handles
*/
#ifndef _DIGSET_STREAM_INTERFACE

	#define _DIGSET_STREAM_INTERFACE "bcrypt"

	void ncCryptoDigestClose(ncc_digest_t* stream)
	{
		DEBUG_ASSERT(stream);
		if (stream)
		{
			if (stream->ctx.hHash) BCryptDestroyHash(stream->ctx.hHash);

			ncCryptoSecureZero(stream, sizeof(ncc_digest_t));
		}
	}

	cstatus_t ncCryptoDigestCreate(ncc_digest_t* stream, uint32_t flags)
	{
		DEBUG_ASSERT(stream);
		if (!stream)
		{
			return CSTATUS_FAIL;
		}

		/* Always zero initialize the stream before use */
		_IMPL_SECURE_ZERO_MEMSET(stream, sizeof(ncc_digest_t));

		/*
		* Chooses from the cng pseudo algorithms as recommended by MSDN
		*/
		switch (flags & NC_CRYPTO_DIGEST_TYPE_MASK)
		{
		case NC_CRYPTO_DIGEST_TYPE_SHA256:

			/* Select the standard or hmac digest handle */
			stream->ctx.hAlg = (flags & NC_CRYPTO_DIGEST_FLAGS_HMAC)
				? BCRYPT_HMAC_SHA256_ALG_HANDLE
				: BCRYPT_SHA256_ALG_HANDLE;
			
			goto Okay;
		}
		
		DEBUG_ASSERT2(0, "Undefined hash algorithm specified");
		return CSTATUS_FAIL;

	Okay:
		DEBUG_ASSERT2(stream->ctx.hAlg, "bcrypt: No algorithm handle was selected");
		stream->flags = flags;
		return CSTATUS_OK;
	}

	cstatus_t ncCryptoDigestInit(ncc_digest_t* stream, cspan_t hmacKey)
	{			
		ULONG		createFlags = 0;
		NTSTATUS	result = 0;

		DEBUG_ASSERT(stream);
		if (!stream)
		{
			return CSTATUS_FAIL;
		}		

		/* Set the reusable flag if the user specified reusable during create */
		if (stream->flags & NC_CRYPTO_DIGEST_FLAGS_REUSE)
		{
			/*
			* NOTE: Users may call init() after finish to "reset" the state and 
			* reuse a hash stream. Bcrypt supports kernel-level object reuse and requires
			* us to skip the CreateHash() step if it was already created. 
			* 
			* If an hmac alg handle exists already, the key will be reused and nothing to
			* do. For standard digests, this is also true.
			* 
			* If we need to create new hash object, set the reusable flag to tell bcrypt
			* to reuse an existing handle.
			* 
			* ALSO NOTE:
			* We exit fast without checking that the user sets the hmac key. This is not
			* shared on all backends and could be an error in the future if we want to 
			* ensure correct. For now, we don't care because it doesn't matter. We could
			* optimize the case on windows where the key is not needed
			*/
			
			if (stream->ctx.hHash) 
			{
				return CSTATUS_OK;
			}

			createFlags |= BCRYPT_HASH_REUSABLE_FLAG;
		}	

		/*
		* bcrypt requires a non-const pointer to the source buffer. This is the only
		* example of when it's acceptable to cast const away, when the API boundary
		* requires it and it happens at the exact call site, nowhere else.
		*
		* HMAC is only initialized if the hmacKey is supplied, otherwise it defaults to
		* a standard digest
		*
		* Setting HashObject to null forces the internal structure to allocate buffers
		* internally.
		* https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash
		*/

		result = BCryptCreateHash(
			stream->ctx.hAlg,
			&stream->ctx.hHash,  /* [out] phHash */
			NULL,                /* pbHashObject */
			0,					 /* cbHashObject */
			(uint8_t*)spanGetOffsetC(hmacKey, 0),
			spanGetSizeC(hmacKey),
			createFlags
		);

		/* Catch some basic error codes for debugging */
		DEBUG_ASSERT2(result != STATUS_INVALID_HANDLE, "The algorithm handle in the hAlgorithm parameter is not valid.");
		DEBUG_ASSERT2(result != STATUS_INVALID_PARAMETER, "One or more parameters are not valid.");

		return BCRYPT_SUCCESS(result);
	}

	cstatus_t ncCryptoDigestUpdate(ncc_digest_t* stream, cspan_t source)
	{
		NTSTATUS result = 0;

		DEBUG_ASSERT(stream);
		if (!stream)
		{
			return CSTATUS_FAIL;
		}

		/* See ncCryptoDigestInit above for acceptable cast away const */

		result = BCryptHashData(
			stream->ctx.hHash,
			(uint8_t*)spanGetOffsetC(source, 0), 
			spanGetSizeC(source),
			0 /* flags */
		);	

		return BCRYPT_SUCCESS(result);
	}

	cstatus_t ncCryptoDigestFinish(ncc_digest_t* stream, span_t output)
	{
		NTSTATUS result = 0;

		DEBUG_ASSERT(stream);
		if (!stream)
		{
			return CSTATUS_FAIL;
		}

		result = BCryptFinishHash(
			stream->ctx.hHash,
			spanGetOffset(output, 0),
			spanGetSize(output),
			0 /* flags */
		);

		DEBUG_ASSERT2(result != STATUS_INVALID_HANDLE, "bcrypt: The hash handle in the hHash parameter is not valid.");
		DEBUG_ASSERT2(result != STATUS_INVALID_PARAMETER, "bcrypt: One or more parameters are not valid. (or output size is incorrect for algorithn type");

		return BCRYPT_SUCCESS(result);
	}

#endif /* !_DIGSET_STREAM_INTERFACE */
