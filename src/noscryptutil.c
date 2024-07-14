/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: noscryptutil.h
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


#include <stdlib.h>

#include "nc-util.h"
#include "nc-crypto.h"

#include <noscryptutil.h>

/*
* Validation macros
*/

#ifdef NC_EXTREME_COMPAT
	#error "Utilities library must be disabled when using extreme compat mode"
#endif /* NC_EXTREME_COMPAT */

#define _nc_mem_free(x) if(x != NULL) { free(x); x = NULL; }
#define _nc_mem_alloc(elements, size) calloc(elements, size);
#define ZERO_FILL ncCryptoSecureZero

#ifndef NC_INPUT_VALIDATION_OFF
	#define CHECK_INVALID_ARG(x, argPos) if(x == NULL) return NCResultWithArgPosition(E_INVALID_ARG, argPos);
	#define CHECK_NULL_ARG(x, argPos) if(x == NULL) return NCResultWithArgPosition(E_NULL_PTR, argPos);
	#define CHECK_ARG_RANGE(x, min, max, argPos) if(x < min || x > max) return NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, argPos);
	#define CHECK_ARG_IS(exp, argPos) if(!(exp)) return NCResultWithArgPosition(E_INVALID_ARG, argPos);
#else
	/* empty macros */
	#define CHECK_INVALID_ARG(x)
	#define CHECK_NULL_ARG(x, argPos) 
	#define CHECK_ARG_RANGE(x, min, max, argPos) 
	#define CHECK_ARG_IS(is, expected, argPos)
#endif /* !NC_DISABLE_INPUT_VALIDATION */


#ifdef _NC_IS_WINDOWS
	
	#include <math.h>

	/* performs a log2 on integer types */
	#define _math_int_log2(x)	(uint32_t)log2((double)x)

#else
	/* 
	* GCC/clang does not expose log2 so we can use the __builtin_clz
	* to find leading zeros of an integer and subtract that from 31 
	* (bit positions) for int32 
	*/
	static _nc_fn_inline uint32_t _math_int_log2(uint32_t val)
	{
		DEBUG_ASSERT(val < UINT32_MAX);

		return 31 - __builtin_clz(val);
	}
#endif

#define MIN_PADDING_SIZE		0x20u
#define NIP44_VERSION_SIZE		0x01u
#define NIP44_PT_LEN_SIZE		sizeof(uint16_t)

/*
* minimum size for a valid nip44 payload
* 1 byte version + 32 byte nonce + 32 byte mac + 2 byte ptSize + 32bytes minimum length
*/
#define NIP44_MIN_PAYLOAD_SIZE  (NIP44_VERSION_SIZE + 0x20 + 0x02 + 0x20 + 0x02)

/*
* The minimum ciphertext size is the minimum padded size + the minimum
* size of the plaintext length field
*/
#define NIP44_MIN_CIPHERTEXT_SIZE (MIN_PADDING_SIZE + NIP44_PT_LEN_SIZE)


/* Currently were on nip44 version 2 */
static const uint8_t Nip44VersionValue[1] = { 0x02u };

struct nc_util_enc_struct {

	uint32_t _flags;

	cspan_t cipherInput;

	/* 
		The data this span points to is allocated during initialization 
	*/
	span_t cipherOutput;

	NCEncryptionArgs encArgs;
};

static _nc_fn_inline span_t _ncUtilAllocSpan(uint32_t count, size_t size)
{
	span_t span;

#if SIZE_MAX < UINT32_MAX

	if (count > SIZE_MAX)
	{
		return span;
	}

#endif

	span.data = _nc_mem_alloc((size_t)count, size);
	span.size = (uint32_t)count;

	return span;
}

static _nc_fn_inline void _ncUtilFreeSpan(span_t span)
{
	_nc_mem_free(span.data);
}

static _nc_fn_inline uint32_t _calcNip44PtPadding(uint32_t plaintextSize)
{
	uint32_t chunk, nextPower, factor;

	/*
	* Taken from https://github.com/nostr-protocol/nips/blob/master/44.md
	*
	* I believe the idea is to add consisten padding for some better 
	* disgusing of the plainText data.
	*/

	if (plaintextSize <= MIN_PADDING_SIZE)
	{
		return MIN_PADDING_SIZE;
	}

	/* Safe to subtract because pt > 0 */
	nextPower = _math_int_log2(plaintextSize - 1);

	nextPower += 1u;

	nextPower = 1 << nextPower;

	if (nextPower <= 256u)
	{
		chunk = 32u;
	}
	else 
	{
		chunk = nextPower / 8u;
	}
	
	factor = plaintextSize - 1;

	factor /= chunk;

	factor += 1;

	return chunk * factor;
}

static _nc_fn_inline uint32_t _calcNip44TotalOutSize(uint32_t inputSize)
{
	uint32_t bufferSize;

	/*
	* Buffer size for nip44 is calculated as follows:
	*   1 byte for the version
	*   32 bytes for the nonce
	*   2 bytes for the length of the plainText
	*   ... padding size
	*   32 bytes for the MAC
	*/

	bufferSize = NIP44_VERSION_SIZE;

	bufferSize += NC_ENCRYPTION_NONCE_SIZE;

	bufferSize += NIP44_PT_LEN_SIZE;

	bufferSize += _calcNip44PtPadding(inputSize);

	bufferSize += NC_ENCRYPTION_MAC_SIZE;

	return bufferSize;
}

static _nc_fn_inline cspan_t _nip44GetMacData(cspan_t payload)
{
	DEBUG_ASSERT(payload.size > NIP44_VERSION_SIZE + NC_ENCRYPTION_MAC_SIZE);

	/*
	* The nip44 mac is computed over the nonce+encrypted ciphertext
	* 
	* the ciphertext is the entire message buffer, so it includes 
	* version, nonce, data, padding, and mac space available.
	* 
	* This function will return a span that points to the nonce+data 
	* segment of the buffer for mac computation.
	* 
	* The nonce sits directly after the version byte, ct is after,
	* and the remaining 32 bytes are for the mac. So that means 
	* macData = ct.size - version.size + mac.size
	*/

	return ncSpanSliceC(
		payload,
		NIP44_VERSION_SIZE,
		payload.size - (NIP44_VERSION_SIZE + NC_ENCRYPTION_MAC_SIZE)
	);
}

static _nc_fn_inline span_t _nip44GetMacOutput(span_t payload)
{
	DEBUG_ASSERT(payload.size > NC_ENCRYPTION_MAC_SIZE);

	/*
	* Mac is the final 32 bytes of the ciphertext buffer
	*/
	return ncSpanSlice(
		payload,
		payload.size - NC_ENCRYPTION_MAC_SIZE,
		NC_ENCRYPTION_MAC_SIZE
	);
}

static _nc_fn_inline cspan_t _nip44ParseMac(cspan_t payload)
{
	DEBUG_ASSERT(payload.size >= NIP44_MIN_PAYLOAD_SIZE);

	/*
	* Mac is the final 32 bytes of the ciphertext buffer
	*/
	return ncSpanSliceC(
		payload,
		payload.size - NC_ENCRYPTION_MAC_SIZE,
		NC_ENCRYPTION_MAC_SIZE
	);
}

static _nc_fn_inline cspan_t _nip44ParseCipherText(cspan_t payload)
{
	DEBUG_ASSERT(payload.size >= NIP44_MIN_PAYLOAD_SIZE);

	/* ct is all of the data after the nonce and before the mac segment */
	return ncSpanSliceC(
		payload,
		NIP44_VERSION_SIZE + NC_ENCRYPTION_NONCE_SIZE,
		payload.size - (NIP44_VERSION_SIZE + NC_ENCRYPTION_NONCE_SIZE + NC_ENCRYPTION_MAC_SIZE)
	);
}

static _nc_fn_inline cspan_t _nip44ParseNonce(cspan_t payload)
{
	DEBUG_ASSERT(payload.size >= NIP44_MIN_PAYLOAD_SIZE);

	/* slice after the version and before the mac segments */
	return ncSpanSliceC(
		payload,
		NIP44_VERSION_SIZE,
		NC_ENCRYPTION_NONCE_SIZE
	);
}

static NCResult _nip44EncryptCompleteCore(
	const NCContext* libContext,
	const NCSecretKey* sk,
	const NCPublicKey* pk,
	NCEncryptionArgs encArgs,
	cspan_t plainText,
	span_t payload
)
{

	NCResult result;
	cspan_t macData, cPayload;
	span_t macOutput;
	uint32_t outPos, paddedCtSize;
	uint8_t ptSize[NIP44_PT_LEN_SIZE];
	uint8_t hmacKeyOut[NC_ENCRYPTION_MAC_SIZE];

	outPos = 0;

	DEBUG_ASSERT(encArgs.version == NC_ENC_VERSION_NIP44);

	ncSpanInitC(&cPayload, payload.data, payload.size);

	/* Padded size is required to know how large the CT buffer is for encryption */
	paddedCtSize = _calcNip44PtPadding(plainText.size);

	/* Start by appending the version number */
	ncSpanAppend(payload, &outPos, Nip44VersionValue, sizeof(Nip44VersionValue));

	/* next is nonce data */
	ncSpanAppend(payload, &outPos, encArgs.nonceData, NC_ENCRYPTION_NONCE_SIZE);
	DEBUG_ASSERT(outPos == 1 + NC_ENCRYPTION_NONCE_SIZE);

	/*
	* Assign the hmac key from the stack buffer. Since the args structure
	* is copied, it won't leak the address to the stack buffer.
	*
	* Should always return success for nip44 because all properties are valid
	* addresses.
	*/

	result = NCSetEncryptionPropertyEx(
		&encArgs,
		NC_ENC_SET_NIP44_MAC_KEY,
		hmacKeyOut,
		sizeof(hmacKeyOut)
	);

	DEBUG_ASSERT(result == NC_SUCCESS);

	/*
	* So this is the tricky part. The encryption operation appens directly
	* on the ciphertext segment
	*
	* All current implementations allow overlapping input and output buffers
	* so we can assign the pt segment on the encryption args
	*/

	/*
	* Since the message size and padding bytes will get encrypted,
	* the buffer should currently point to the start of the encryption segment
	*
	* The size of the data to encrypt is the padded size plus the size of the
	* plainText size field.
	*/

	result = NCSetEncryptionData(
		&encArgs,
		(payload.data + outPos),			/* in place encryption */
		(payload.data + outPos),
		paddedCtSize + NIP44_PT_LEN_SIZE	/* Plaintext + pt size must be encrypted */
	);

	DEBUG_ASSERT(result == NC_SUCCESS);

	/* big endian plaintext size */
	ptSize[0] = (uint8_t)(plainText.size >> 8);
	ptSize[1] = (uint8_t)(plainText.size & 0xFF);

	/*
	* Written position must point to the end of the padded ciphertext
	* area which the plaintext is written to.
	*
	* The plaintext data will be encrypted in place. The encrypted
	* data is the entired padded region containing the leading byte count
	* the plaintext data, followed by zero padding.
	*/

	ncSpanWrite(payload, outPos, ptSize, NIP44_PT_LEN_SIZE);

	ncSpanWrite(
		payload,
		outPos + NIP44_PT_LEN_SIZE,		/* write pt directly after length */
		plainText.data,
		plainText.size
	);

	/* Move position pointer directly after final padding bytes */
	outPos += encArgs.dataSize;

	result = NCEncrypt(libContext, sk, pk, &encArgs);

	if (result != NC_SUCCESS)
	{
		return result;
	}

	/*
		MAC is computed over the nonce+encrypted data
		this helper captures that data segment into a span
	*/

	macData = _nip44GetMacData(cPayload);
	macOutput = _nip44GetMacOutput(payload);

	result = NCComputeMac(
		libContext,
		hmacKeyOut,
		macData.data,
		macData.size,
		macOutput.data
	);

	if (result != NC_SUCCESS)
	{
		return result;
	}

	outPos += NC_ENCRYPTION_MAC_SIZE;

	DEBUG_ASSERT2(outPos == payload.size, "Buffer under/overflow detected");

	/* zero hmac key before returning */
	ZERO_FILL(hmacKeyOut, sizeof(hmacKeyOut));

	/* Notify the caller how many bytes were written */
	return NC_SUCCESS;
}

static NCResult _nip44DecryptCompleteCore(
	const NCContext* libContext,
	const NCSecretKey* recvKey,
	const NCPublicKey* sendKey,
	const NCUtilCipherContext* cipher
)
{
	NCResult result;
	NCMacVerifyArgs macArgs;
	NCEncryptionArgs encArgs;
	cspan_t macData, macValue, cipherText, nonce;

	DEBUG_ASSERT(libContext && recvKey && sendKey && cipher);
	DEBUG_ASSERT(cipher->encArgs.version == NC_ENC_VERSION_NIP44);

	/* ensure decryption mode */
	DEBUG_ASSERT(cipher->_flags & NC_UTIL_CIPHER_MODE_DECRYPT);

	/* store local stack copy for safe mutation */
	encArgs = cipher->encArgs;

	nonce = _nip44ParseNonce(cipher->cipherInput);

	/* Verify mac if the user allowed it */
	if ((cipher->_flags & NC_UTIL_CIPHER_MAC_NO_VERIFY) == 0)
	{
		/*
		* The mac data to verify against is the nonce+ciphertext data
		* from within the nip44 message payload
		*/

		macData = _nip44GetMacData(cipher->cipherInput);
		macValue = _nip44ParseMac(cipher->cipherInput);

		DEBUG_ASSERT(macValue.size == NC_ENCRYPTION_MAC_SIZE);
		DEBUG_ASSERT(macData.size > NC_ENCRYPTION_NONCE_SIZE + 0x20);

		/* Assign the mac data to the mac verify args */
		macArgs.mac32 = macValue.data;
		macArgs.nonce32 = nonce.data;
		
		/* payload for verifying a mac in nip44 is the nonce+ciphertext */
		macArgs.payload = macData.data;
		macArgs.payloadSize = macData.size;

		/* Verify the mac */
		result = NCVerifyMac(libContext, recvKey, sendKey, &macArgs);

		/* When the mac is invlaid */
		if (result == E_OPERATION_FAILED)
		{
			return E_CIPHER_MAC_INVALID;
		}
		/* argument errors */
		else if (result != NC_SUCCESS)
		{
			return result;
		}
	}

	cipherText = _nip44ParseCipherText(cipher->cipherInput);
	
	DEBUG_ASSERT2(cipherText.size >= MIN_PADDING_SIZE, "Cipertext segment was parsed incorrectly. Too small");

	/* manually sign nonce */
	encArgs.nonceData = nonce.data;

	/*
	* Remember the decryption operation is symmetric, it reads the input bytes and writes 
	* directly to the output. 
	* 
	* The decryption is performed on the ciphertext segment and we can write the output 
	* directly the output buffer.
	* 
	* The leading 2 bytes will be the encoded plaintext size, followed by the plaintext data
	* and padding. That's okay. The user will call NCUtilCipherGetOutputSize to get the
	* actual size of the plaintext, which will exlcude the leading 2 bytes and padding.
	*/

	DEBUG_ASSERT(cipher->cipherOutput.size >= cipherText.size);

	result = NCSetEncryptionData(
		&encArgs,
		cipherText.data,
		cipher->cipherOutput.data,
		cipherText.size
	);

	if (result != NC_SUCCESS)
	{
		return result;
	}

	/*
	* If decryption was successful, the data should be written 
	* directly to the output buffer
	*/
	result = NCDecrypt(libContext, recvKey, sendKey, &encArgs);

	return result;
}

NC_EXPORT NCResult NC_CC NCUtilGetEncryptionPaddedSize(uint32_t encVersion, uint32_t plaintextSize)
{
	switch (encVersion)
	{
	default:
		return E_VERSION_NOT_SUPPORTED;

	case NC_ENC_VERSION_NIP04:
		return plaintextSize;

	case NC_ENC_VERSION_NIP44:

		return (NCResult)(_calcNip44PtPadding(plaintextSize));
	}
}

NC_EXPORT NCResult NC_CC NCUtilGetEncryptionBufferSize(uint32_t encVersion, uint32_t plaintextSize)
{

	switch (encVersion)
	{
	default:
		return E_VERSION_NOT_SUPPORTED;

		/*
		* NIP-04 simply uses AES to 1:1 encrypt the plainText
		* to ciphertext.
		*/
	case NC_ENC_VERSION_NIP04:
		return plaintextSize;

	case NC_ENC_VERSION_NIP44:
		return (NCResult)(_calcNip44TotalOutSize(plaintextSize));
	}
}


NC_EXPORT NCUtilCipherContext* NC_CC NCUtilCipherAlloc(uint32_t encVersion, uint32_t flags)
{
	NCUtilCipherContext* encCtx;

	/*
	* Alloc context on heap
	*/
	encCtx = (NCUtilCipherContext*)_nc_mem_alloc(1, sizeof(NCUtilCipherContext));

	if (encCtx != NULL)
	{
		encCtx->encArgs.version = encVersion;
		encCtx->_flags = flags;
	}

	return encCtx;
}

NC_EXPORT void NC_CC NCUtilCipherFree(NCUtilCipherContext* encCtx)
{
	if (!encCtx) 
	{
		return;
	}

	/*
	* If zero on free flag is set, we can zero all output memory 
	* before returning the buffer back to the heap
	*/
	if ((encCtx->_flags & NC_UTIL_CIPHER_ZERO_ON_FREE) > 0 && encCtx->cipherOutput.data) 
	{
		ZERO_FILL(encCtx->cipherOutput.data, encCtx->cipherOutput.size);
	}

	/* Free output buffers */
	_ncUtilFreeSpan(encCtx->cipherOutput);

	/* context can be released */
	_nc_mem_free(encCtx);
}

NC_EXPORT NCResult NC_CC NCUtilCipherInit(
	NCUtilCipherContext* encCtx,
	const uint8_t* inputData,
	uint32_t inputSize
)
{
	NCResult outputSize;

	CHECK_NULL_ARG(encCtx, 0);
	CHECK_NULL_ARG(inputData, 1);
	/* The output state must not have alraedy been allocated */
	CHECK_ARG_IS(encCtx->cipherOutput.data == NULL, 0);

	if ((encCtx->_flags & NC_UTIL_CIPHER_MODE_DECRYPT) > 0)
	{
		/*
		* Validate the input data for proper format for 
		* the current cipher version
		*/
		switch (encCtx->encArgs.version)
		{
		case NC_ENC_VERSION_NIP44:
		{
			if (inputSize < NIP44_MIN_PAYLOAD_SIZE)
			{
				return E_CIPHER_INVALID_FORMAT;
			}

			if (inputSize > NIP44_MAX_ENC_MESSAGE_SIZE)
			{
				return E_CIPHER_INVALID_FORMAT;
			}

			/* Ensure the first byte is a valid version */
			if (inputData[0] != Nip44VersionValue[0])
			{
				return E_VERSION_NOT_SUPPORTED;
			}

			break;
		}
		default:
			return E_VERSION_NOT_SUPPORTED;
		}

		/*
		* Alloc a the output buffer to be the same size as the input
		* data for decryption because the output will always be equal
		* or smaller than the input data. This is an over-alloc but 
		* that should be fine
		*/

		outputSize = inputSize;
	}
	else
	{
		/*
		* Calculate the correct output size to store the encryption
		* data for the given cipher version
		*/
		outputSize = NCUtilGetEncryptionBufferSize(encCtx->encArgs.version, inputSize);
	}

	if (outputSize <= 0)
	{
		return outputSize;
	}

	/* Alloc output buffer within the struct */
	encCtx->cipherOutput = _ncUtilAllocSpan((uint32_t)outputSize, sizeof(uint8_t));

	if (!encCtx->cipherOutput.data)
	{
		return E_OUT_OF_MEMORY;
	}

	ncSpanInitC(&encCtx->cipherInput, inputData, inputSize);

	return NC_SUCCESS;
}

NC_EXPORT NCResult NC_CC NCUtilCipherGetFlags(const NCUtilCipherContext* ctx)
{
	CHECK_NULL_ARG(ctx, 0);

	return (NCResult)(ctx->_flags);
}

NC_EXPORT NCResult NC_CC NCUtilCipherGetOutputSize(const NCUtilCipherContext* encCtx)
{
	uint16_t nip44PtSize;

	CHECK_NULL_ARG(encCtx, 0);

	/*
	* if nip44 decryption is desired, the output buffer will be 
	* overallocated. It will also contain some padding bytes
	* so we need to parse the plaintext size from the buffer
	* and return that as the output size.
	*/
	if (encCtx->encArgs.version == NC_ENC_VERSION_NIP44 
		&& (encCtx->_flags & NC_UTIL_CIPHER_MODE_DECRYPT) > 0)
	{

		/* ensure the output has been allocated correctly */
		if (encCtx->cipherOutput.size < NIP44_PT_LEN_SIZE)
		{
			return E_INVALID_CONTEXT;
		}

		/*
		* If a decryption operation was performed the leading 2 bytes will
		* be the big-endian encoded plaintext size. This function should 
		* return the size of the plaintext data, not the entire buffer.
		*/

		nip44PtSize = (encCtx->cipherOutput.data[0] << 8) | encCtx->cipherOutput.data[1];

		/*
		* If improperly decryption/formatted, the pt size may be some really large 
		* number when decoded, so make sure it doesn't point to a location outside
		* the buffer, that would be invalid
		*/
		if (nip44PtSize > (encCtx->cipherOutput.size - NIP44_PT_LEN_SIZE))
		{
			return E_CIPHER_INVALID_FORMAT;
		}

		return (NCResult)nip44PtSize;
	}

	return (NCResult)(encCtx->cipherOutput.size);
}

NC_EXPORT NCResult NC_CC NCUtilCipherReadOutput(
	const NCUtilCipherContext* encCtx,
	uint8_t* output,
	uint32_t outputSize
)
{
	NCResult result;

	CHECK_NULL_ARG(encCtx, 0)
	CHECK_NULL_ARG(output, 1)

	/*
	* Again if in nip44 decrypt mode we only want the 
	* actual plaintext data
	*/

	if (encCtx->encArgs.version == NC_ENC_VERSION_NIP44
		&& (encCtx->_flags & NC_UTIL_CIPHER_MODE_DECRYPT) > 0)
	{
		result = NCUtilCipherGetOutputSize(encCtx);
		
		if (result < 0) 
		{
			return result;
		}

		DEBUG_ASSERT((result + NIP44_PT_LEN_SIZE) < encCtx->cipherOutput.size);

		/* Make sure the output buffer is large enough */
		CHECK_ARG_RANGE(outputSize, result, UINT32_MAX, 2);

		/*
		* Plaintext data sits directly after the length bytes 
		* and up to the length of the plaintext size
		*/
		MEMMOV(
			output,
			encCtx->cipherOutput.data + NIP44_PT_LEN_SIZE,
			(uint32_t)result
		);

		return result;
	}
	else
	{
		CHECK_ARG_RANGE(outputSize, encCtx->cipherOutput.size, UINT32_MAX, 2);

		MEMMOV(
			output,
			encCtx->cipherOutput.data,
			encCtx->cipherOutput.size
		);

		return (NCResult)encCtx->cipherOutput.size;
	}
}

NC_EXPORT NCResult NCUtilCipherSetProperty(
	NCUtilCipherContext* ctx,
	uint32_t property,
	uint8_t* value,
	uint32_t valueLen
)
{	
	CHECK_NULL_ARG(ctx, 0)

	/* All other arguments are verified */
	return NCSetEncryptionPropertyEx(
		&ctx->encArgs, 
		property, 
		value, 
		valueLen
	);
}

NC_EXPORT NCResult NC_CC NCUtilCipherUpdate(
	const NCUtilCipherContext* encCtx,
	const NCContext* libContext,
	const NCSecretKey* sk,
	const NCPublicKey* pk
)
{
	CHECK_NULL_ARG(encCtx, 0);
	CHECK_NULL_ARG(libContext, 1);
	CHECK_NULL_ARG(sk, 2);
	CHECK_NULL_ARG(pk, 3);

	/* Make sure input & output buffers have been assigned/allocated */
	if (encCtx->cipherOutput.data == NULL)
	{
		return E_INVALID_CONTEXT;
	}
	if (encCtx->cipherInput.data == NULL)
	{
		return E_INVALID_CONTEXT;
	}

	switch (encCtx->encArgs.version)
	{
	case NC_ENC_VERSION_NIP44:

		if ((encCtx->_flags & NC_UTIL_CIPHER_MODE_DECRYPT) > 0)
		{
			return _nip44DecryptCompleteCore(libContext, sk, pk, encCtx);
		}
		else
		{
			/* Ensure the user manually specified a nonce buffer for encryption mode */
			if (!encCtx->encArgs.nonceData)
			{
				return E_CIPHER_BAD_NONCE;
			}

			return _nip44EncryptCompleteCore(
				libContext,
				sk,
				pk,
				encCtx->encArgs,
				encCtx->cipherInput,
				encCtx->cipherOutput
			);
		}

	default:
		return E_VERSION_NOT_SUPPORTED;
	}
}
