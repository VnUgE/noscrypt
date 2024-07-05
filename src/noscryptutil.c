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


#include <noscryptutil.h>
#include "nc-util.h"
#include "nc-crypto.h"

/*
* Validation macros
*/

#ifdef NC_EXTREME_COMPAT
	#error "Utilities library must be disabled when using extreme compat mode"
#endif /* NC_EXTREME_COMPAT */

#include <stdlib.h>
#include <math.h>

#define _nc_mem_free(x) if(x != NULL) { free(x); x = NULL; }
#define _nc_mem_alloc(elements, size) calloc(elements, size);

#ifndef NC_INPUT_VALIDATION_OFF
	#define CHECK_INVALID_ARG(x, argPos) if(x == NULL) return NCResultWithArgPosition(E_INVALID_ARG, argPos);
	#define CHECK_NULL_ARG(x, argPos) if(x == NULL) return NCResultWithArgPosition(E_NULL_PTR, argPos);
	#define CHECK_ARG_RANGE(x, min, max, argPos) if(x < min || x > max) return NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, argPos);
#else
	/* empty macros */
	#define CHECK_INVALID_ARG(x)
	#define CHECK_NULL_ARG(x, argPos) 
	#define CHECK_ARG_RANGE(x, min, max, argPos) 
#endif /* !NC_DISABLE_INPUT_VALIDATION */


/* performs a log2 on integer types */
#define _math_int_log2(x)	(int32_t)log2((double)x)

#define MIN_PADDING_SIZE		0x20
#define NIP44_VERSION_SIZE		0x01
#define NIP44_PT_LEN_SIZE		0x02

/* Currently were on nip44 version 2 */
const static uint8_t Nip44VersionValue = 0x02;

typedef struct nc_util_enc_buffer_state 
{
	uint8_t* ciphertext;
	uint32_t ciphertextSize;

} NCCipherTextOutState;

struct nc_util_enc_struct {
	
	/* Dynamically allocated during initialization */
	NCCipherTextOutState* outState;

	const uint8_t* plaintext;
	
	uint32_t plaintextSize;

	NCEncryptionArgs encArgs;
};

static _nc_fn_inline int32_t _calcNip44PtPadding(int32_t plaintextSize)
{
	int32_t chunk, nextPower, factor;

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

	nextPower = _math_int_log2(plaintextSize - 1);

	nextPower += 1;

	nextPower = 1 << nextPower;

	if (nextPower <= 256)
	{
		chunk = 32;
	}
	else 
	{
		chunk = nextPower / 8;
	}
	
	factor = plaintextSize - 1;

	factor /= chunk;

	factor += 1;

	return chunk * factor;
}

static _nc_fn_inline int32_t _calcNip44TotalOutSize(int32_t inputSize)
{
	int32_t bufferSize;

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

static NCResult _nip44EncryptCompleteCore(
	const NCContext* libContext,
	const NCSecretKey* sk,
	const NCPublicKey* pk,
	NCEncryptionArgs encArgs,
	span_t cipherText,
	span_t plainText
)
{

	NCResult result;
	uint32_t outPos, paddedCtSize;
	uint16_t ptSize;
	
	outPos = 0;
	
	DEBUG_ASSERT(encArgs.version == NC_ENC_VERSION_NIP44);

	/* Padded size is required to know how large the CT buffer is for encryption */
	paddedCtSize = (int32_t)_calcNip44PtPadding((int32_t)plainText.size);

	/* Start by appending the version number */
	ncSpanAppend(cipherText, &outPos, &Nip44VersionValue, 0x01);

	/* next is nonce data */
	ncSpanAppend(cipherText, &outPos, encArgs.nonceData, NC_ENCRYPTION_NONCE_SIZE);
	DEBUG_ASSERT(outPos == 1 + NC_ENCRYPTION_NONCE_SIZE);

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

	encArgs.inputData = (cipherText.data + outPos);
	encArgs.outputData = (cipherText.data + outPos);
	encArgs.dataSize = paddedCtSize + sizeof(uint16_t);	/* Plaintext + pt size must be encrypted */

	ptSize = (uint16_t)plainText.size;

	/* Can write the plainText size to buffer now */
	ncSpanAppend(cipherText, &outPos, &ptSize, sizeof(uint16_t));

	/* concat plainText */
	ncSpanAppend(cipherText, &outPos, plainText.data, plainText.size);

	/* Time to perform encryption operation */
	result = NCEncrypt(libContext, sk, pk, &encArgs);

	if (result == NC_SUCCESS)
	{

	}
}

static NCResult _nip44EncryptCompleteCore(
	NCUtilEncryptionContext* encCtx,
	const NCContext* libContext,
	const NCSecretKey* sk,
	const NCPublicKey* pk
)
{
	span_t cipherText, plainText;

	/* Set up spans */
	ncSpanInit(
		&cipherText, 
		encCtx->outState->ciphertext,
		encCtx->outState->ciphertextSize
	);

	ncSpanInit(
		&plainText, 
		encCtx->plaintext, 
		encCtx->plaintextSize
	);

	return _nip44EncryptCompleteCore(
		libContext, 
		sk, 
		pk, 
		encCtx->encArgs, 
		cipherText, 
		plainText
	);
}

NC_EXPORT NCResult NC_CC NCUtilGetEncryptionPaddedSize(uint32_t encVersion, int32_t plaintextSize)
{
	int32_t paddingSize;

	CHECK_ARG_RANGE(plaintextSize, 0, INT32_MAX, 1)

	switch (encVersion)
	{
		default:
			return E_VERSION_NOT_SUPPORTED;

		case NC_ENC_VERSION_NIP04:
			return plaintextSize;

		case NC_ENC_VERSION_NIP44:
			paddingSize = _calcNip44PtPadding(plaintextSize);

			DEBUG_ASSERT(paddingSize > 0)

			return (NCResult)(paddingSize);
	}
}

NC_EXPORT NCResult NC_CC NCUtilGetEncryptionBufferSize(uint32_t encVersion, int32_t plaintextSize)
{
	int32_t totalSize;

	CHECK_ARG_RANGE(plaintextSize, 0, INT32_MAX, 1)

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
			totalSize = _calcNip44TotalOutSize(plaintextSize);

			DEBUG_ASSERT(totalSize > 0)

			return (NCResult)(totalSize);

	}
}


NC_EXPORT NCUtilEncryptionContext* NC_CC NCUtilAllocEncryptionContext(uint32_t encVersion)
{
	NCUtilEncryptionContext* encCtx;

	/*
	* Alloc context on heap
	*/
	encCtx = (NCUtilEncryptionContext*)_nc_mem_alloc(1, sizeof(NCUtilEncryptionContext));

	if (encCtx != NULL)
	{
		encCtx->encArgs.version = encVersion;
	}

	return encCtx;
}

NC_EXPORT void NC_CC NCUtilFreeEncryptionContext(NCUtilEncryptionContext* encCtx)
{
	if (!encCtx) 
	{
		return;
	}

	/* Free output buffers */
	_nc_mem_free(encCtx->outState);

	/* context can be released */
	_nc_mem_free(encCtx);
}

NC_EXPORT NCResult NC_CC NCUtilInitEncryptionContext(
	NCUtilEncryptionContext* encCtx,
	const uint8_t* plainText,
	uint32_t plainTextSize
)
{

	NCResult outputSize;
	NCCipherTextOutState* output;

	CHECK_NULL_ARG(encCtx, 0)
	CHECK_NULL_ARG(plainText, 1)
	CHECK_ARG_RANGE(plainTextSize, 0, INT32_MAX, 2)

	/*
	* The output state must not have alraedy been allocated
	*/
	if (encCtx->outState) 
	{
		return E_INVALID_ARG;
	}

	/*
	* Calculate the correct output size to store the encryption 
	* data for the given cipher version
	*/
	outputSize = NCUtilGetEncryptionBufferSize(encCtx->encArgs.version, plainTextSize);

	if (outputSize <= 0)
	{
		return outputSize;
	}

	/*Alloc output buffer within the struct */
	output = (NCCipherTextOutState*)_nc_mem_alloc(sizeof(NCCipherTextOutState) + (int)outputSize, 1);

	if (!output)
	{
		return E_OUT_OF_MEMORY;
	}

	/* set cipertext buffer to end of the structure memory */
	output->ciphertext = (uint8_t*)(output + 1);
	output->ciphertextSize = outputSize;

	encCtx->outState = output;
	encCtx->plaintext = plainText;
	encCtx->plaintextSize = plainTextSize;
	
	return NC_SUCCESS;
}

NC_EXPORT NCResult NC_CC NCUtilGetEncryptedSize(const NCUtilEncryptionContext* encCtx)
{
	CHECK_NULL_ARG(encCtx, 0);

	return (NCResult)(encCtx->outState->ciphertextSize);
}

NC_EXPORT NCResult NC_CC NCUtilReadEncryptedData(
	const NCUtilEncryptionContext* encCtx,
	uint8_t* output,
	uint32_t outputSize
)
{
	CHECK_NULL_ARG(encCtx, 0)
	CHECK_NULL_ARG(output, 1)
	CHECK_ARG_RANGE(outputSize, 0, INT32_MAX, 2)

	if (outputSize < encCtx->outState->ciphertextSize)
	{
		return E_OPERATION_FAILED;
	}

	MEMMOV(output, encCtx->outState->ciphertext, encCtx->outState->ciphertextSize);

	return (NCResult)encCtx->outState->ciphertextSize;
}

NC_EXPORT NCResult NCUtilSetEncryptionProperty(
	NCUtilEncryptionContext* ctx,
	uint32_t property,
	uint8_t* value,
	uint32_t valueLen
)
{
	
	CHECK_NULL_ARG(ctx, 0)

	/* All other arguments are verified */
	return NCSetEncryptionPropertyEx(&ctx->encArgs, property, value, valueLen);
}
