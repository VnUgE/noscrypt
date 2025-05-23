﻿/*
* Copyright (c) 2025 Vaughn Nugent
*
* Package: noscrypt
* File: noscrypt.c
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

#include "noscrypt.h"

#include "nc-util.h"
#include "hkdf.h"
#include "nc-crypto.h"

#include <secp256k1/include/secp256k1_ecdh.h>
#include <secp256k1/include/secp256k1_schnorrsig.h>

/*
* CLARIFICATION:
* Nip44 requires a "nonce" this is different from 
* the chacha20 nonce parameter. The nip44 nonce can 
* be accuratly described as an initialization vector.
* So we will be using the term IV to describe the nip44
* public facing "nonce" parameter.
* 
* Since this size differs, I want to define clarifying 
* macros to help with the code readability.
*/

#define NIP44_IV_SIZE       0x20u
#define NIP04_IV_SIZE       NC_CRYPTO_AES_IV_SIZE

/*
* Local macro for secure zero buffer fill
*/
#define ZERO_FILL(x, size) ncCryptoSecureZero(x, size) 

/*
* Validation macros
*/

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

#define CHECK_CONTEXT_STATE(ctx, argPos) CHECK_INVALID_ARG(ctx->secpCtx, argPos)

/*
* Actual, private defintion of the NCContext structure 
* to allow for future development and ABI backwards 
* compatability.
*/
struct nc_ctx_struct {

	void* secpCtx;

};

/*
* The Nip44 constant salt
* https://github.com/nostr-protocol/nips/blob/master/44.md#encryption
*/
static const uint8_t Nip44ConstantSalt[8] = { 0x6e, 0x69, 0x70, 0x34, 0x34, 0x2d, 0x76, 0x32 };

static struct nc_ctx_struct _ncSharedCtx;

struct shared_secret {
	uint8_t value[NC_SHARED_SEC_SIZE];
};

struct conversation_key {
	uint8_t value[NC_CONV_KEY_SIZE];
};

struct message_key {
	uint8_t value[NC_MESSAGE_KEY_SIZE];
};

/*
* The following struct layout is exactly the same as 
* the message key, they may be typecasted to each other.
* as long as the size is the same.
*/
struct nc_expand_keys {
	uint8_t chacha_key[NC_CRYPTO_CHACHA_KEY_SIZE];
	uint8_t chacha_nonce[NC_CRYPTO_CHACHA_NONCE_SIZE];
	uint8_t hmac_key[NC_HMAC_KEY_SIZE];
};


/* Pointer typecast must work between expanded keys 
* and message key, size must be identical to work 
*/
STATIC_ASSERT(sizeof(struct nc_expand_keys) == sizeof(struct message_key), "Expected struct nc_expand_keys to be the same size as struct message_key")

/*
* Check that the fallback hkdf extract internal buffer is large enough
* for full converstation key buffers 
*/
STATIC_ASSERT(HKDF_IN_BUF_SIZE >= NC_CONV_KEY_SIZE + 8, "HKDF Buffer size is too small for safe HKDF operations")

/*
* Internal helper functions to do common structure conversions
*/

static _nc_fn_inline int _convertToXonly(
	const NCContext* ctx, 
	const NCPublicKey* compressedPubKey, 
	secp256k1_xonly_pubkey* xonly
)
{
	DEBUG_ASSERT2(ctx != NULL, "Expected valid context")
	DEBUG_ASSERT2(compressedPubKey != NULL, "Expected a valid public 32byte key structure")
	DEBUG_ASSERT2(xonly != NULL, "Expected valid X-only secp256k1 public key structure ")

	/* Parse the public key into the x-only structure */
	return secp256k1_xonly_pubkey_parse(ctx->secpCtx, xonly, compressedPubKey->key);
}

static int _convertToPubKey(const NCContext* ctx, const NCPublicKey* compressedPubKey, secp256k1_pubkey* pubKey)
{
	int result;
	uint8_t compressed[sizeof(NCPublicKey) + 1];

	DEBUG_ASSERT2(ctx != NULL, "Expected valid context")
	DEBUG_ASSERT2(compressedPubKey != NULL, "Expected a valid public 32byte key structure")
	DEBUG_ASSERT2(pubKey != NULL, "Expected valid secp256k1 public key structure")

	/* Set the first byte to 0x02 to indicate a compressed public key */
	compressed[0] = BIP340_PUBKEY_HEADER_BYTE;

	/* Copy the compressed public key data into a new buffer (offset by 1 to store the header byte) */
	MEMMOV((compressed + 1), compressedPubKey, sizeof(NCPublicKey));

	result = secp256k1_ec_pubkey_parse(ctx->secpCtx, pubKey, compressed, sizeof(compressed));
	
	ZERO_FILL(compressed, sizeof(compressed));

	return result;
}

static _nc_fn_inline int _convertFromXonly(
	const NCContext* ctx, 
	const secp256k1_xonly_pubkey* xonly, 
	NCPublicKey* compressedPubKey
)
{
	DEBUG_ASSERT2(ctx != NULL, "Expected valid context")
	DEBUG_ASSERT2(xonly != NULL, "Expected valid X-only secp256k1 public key structure.")
	DEBUG_ASSERT2(compressedPubKey != NULL, "Expected a valid public 32byte pubkey structure")

	return secp256k1_xonly_pubkey_serialize(ctx->secpCtx, compressedPubKey->key, xonly);
}

/*
* IMPL NOTES:
* This callback function will be invoked by the ecdh function to hash the shared point.
*
* For nostr, this operation is defined in the new NIP-44 spec here:
* https://github.com/nostr-protocol/nips/blob/master/44.md#encryption
*
* The x coordinate of the shared point is copied directly into the output buffer. No hashing is
* performed here. The y coordinate is not used, and for this implementation, there is no data
* pointer.
*/
static int _edhHashFuncInternal(
	unsigned char* output,
	const uint8_t* x32,
	const uint8_t* y32,
	void* data
)
{
	((void)y32);	/* unused for nostr */
	((void)data);

	DEBUG_ASSERT2(output != NULL, "Expected valid output buffer")
	DEBUG_ASSERT2(x32 != NULL, "Expected a valid public 32byte x-coodinate buffer")

	/* Copy the x coordinate of the shared point into the output buffer */
	MEMMOV(output, x32, 32);

	return 32;	/* Return the number of bytes written to the output buffer */
}

static NCResult _computeSharedSecret(
	const NCContext* ctx,
	const NCSecretKey* sk,
	const NCPublicKey* otherPk,
	struct shared_secret* sharedPoint
)
{
	int result;
	secp256k1_pubkey pubKey;

	DEBUG_ASSERT(ctx != NULL)
	DEBUG_ASSERT(sk != NULL)
	DEBUG_ASSERT(otherPk != NULL)
	DEBUG_ASSERT(sharedPoint != NULL)

	/* Recover pubkey from compressed public key data */
	if (_convertToPubKey(ctx, otherPk, &pubKey) != 1)
	{
		return E_INVALID_ARG;
	}

	/*
	* Compute the shared point using the ecdh function.
	*
	* The above callback is invoked to "compute" the hash (it
	* copies the x coord) and it does not use the data pointer
	* so it is set to NULL.
	*/
	result = secp256k1_ecdh(
		ctx->secpCtx,
		sharedPoint->value,
		&pubKey,
		sk->key,
		&_edhHashFuncInternal,
		NULL
	);
	
	ZERO_FILL(&pubKey, sizeof(pubKey));

	/* Result should be 1 on success */
	return result == 1 ? NC_SUCCESS : E_OPERATION_FAILED;
}

static _nc_fn_inline NCResult _computeConversationKey(
	const NCContext* ctx, 
	const struct shared_secret* sharedSecret,
	struct conversation_key* ck 
)
{
	cspan_t saltSpan, ikmSpan;
	
	DEBUG_ASSERT2(ctx != NULL, "Expected valid context")
	DEBUG_ASSERT2(sharedSecret != NULL, "Expected a valid shared-point")
	DEBUG_ASSERT2(ck != NULL, "Expected a valid conversation key")

	ncSpanInitC(&saltSpan, Nip44ConstantSalt, sizeof(Nip44ConstantSalt));
	ncSpanInitC(&ikmSpan, sharedSecret->value, NC_SHARED_SEC_SIZE);
	
	return ncCryptoSha256HkdfExtract(saltSpan, ikmSpan, ck->value) == CSTATUS_OK 
		? NC_SUCCESS 
		: E_OPERATION_FAILED;
}


/*
* Explode the hkdf into the chacha key, chacha nonce, and hmac key.
*/
static _nc_fn_inline const struct nc_expand_keys* _expandKeysFromHkdf(const struct message_key* hkdf)
{
	return (const struct nc_expand_keys*)hkdf;
}

static cstatus_t _chachaEncipher(const struct nc_expand_keys* keys, const NCEncryptionArgs* args)
{
	span_t outputSpan;
	cspan_t inputSpan, keySpan, nonceSpan;

	DEBUG_ASSERT2(keys != NULL, "Expected valid keys");
	DEBUG_ASSERT2(args != NULL, "Expected valid encryption args");

	ncSpanInit(&outputSpan, args->outputData, args->dataSize);
	ncSpanInitC(&inputSpan, args->inputData, args->dataSize);
	ncSpanInitC(&keySpan, keys->chacha_key, NC_CRYPTO_CHACHA_KEY_SIZE);
	ncSpanInitC(&nonceSpan, keys->chacha_nonce, NC_CRYPTO_CHACHA_NONCE_SIZE);

	return ncCryptoChacha20(keySpan, nonceSpan, inputSpan, outputSpan);
}

static _nc_fn_inline cstatus_t _getMessageKey(
	const struct conversation_key* converstationKey, 
	cspan_t nonce,
	struct message_key* messageKey
)
{
	cspan_t prkSpan;
	span_t okmSpan;

	DEBUG_ASSERT2(converstationKey != NULL, "Expected valid conversation key")
	DEBUG_ASSERT2(messageKey != NULL, "Expected valid message key buffer")

	ncSpanInitC(&prkSpan, converstationKey->value, sizeof(struct conversation_key));	/* Conversation key is the input key */
	ncSpanInit(&okmSpan, messageKey->value, sizeof(struct message_key));				/* Output produces a message key (write it directly to struct memory) */
	
	/* Nonce is the info */
	return ncCryptoSha256HkdfExpand(prkSpan, nonce, okmSpan);
}

static _nc_fn_inline NCResult _nip44CipherUpdate(
	const NCContext* ctx, 
	const struct conversation_key* ck, 
	NCEncryptionArgs* args,
	int encrypt
)
{
	NCResult result;
	cspan_t nonceSpan;
	struct message_key messageKey;
	const struct nc_expand_keys* cipherKeys;

	DEBUG_ASSERT2(ctx != NULL, "Expected valid context");
	DEBUG_ASSERT2(ck != NULL, "Expected valid conversation key");
	DEBUG_ASSERT2(args != NULL, "Expected valid encryption args");
	DEBUG_ASSERT(args->version == NC_ENC_VERSION_NIP44);

	result = NC_SUCCESS;

	ncSpanInitC(
		&nonceSpan, 
		args->ivData,
		NCEncryptionGetIvSize(args->version)
	);

	/* 
	 * Since were on nip-44 branch, the nonce field should always 
	 * be equal to the nip44 "nonce" parameter
	 */
	DEBUG_ASSERT2(ncSpanGetSizeC(nonceSpan) == NIP44_IV_SIZE, "Expected valid nip44 nonce size");
	
	/* Message key will be derrived on every encryption call */
	if (_getMessageKey(ck, nonceSpan, &messageKey) != CSTATUS_OK)
	{
		result = E_OPERATION_FAILED;
		goto Cleanup;
	}

	/* Expand the keys from the hkdf so we can use them in the cipher */
	cipherKeys = _expandKeysFromHkdf(&messageKey);

	/*
	* For encryption mode, the key data must also be stored in the key buffer
	* so the caller can save the hmac key for later verification.
	*/
	if (encrypt)
	{
		DEBUG_ASSERT2(args->keyData != NULL, "Expected valid hmac key buffer");

		MEMMOV(args->keyData, cipherKeys->hmac_key, NC_HMAC_KEY_SIZE);
	}

	/* CHACHA20 (the result will be 0 on success) */
	if (_chachaEncipher(cipherKeys, args) != CSTATUS_OK)
	{
		result = E_OPERATION_FAILED;
	}

Cleanup:
	ZERO_FILL(&messageKey, sizeof(messageKey));

	return result;
}


static _nc_fn_inline NCResult _nip04CipherUpdate(
	const NCContext* ctx,
	NCEncryptionArgs* args,
	int encrypt
) 
{
	int encFlags;
	span_t outputSpan;
	cspan_t ivSpan, inputSpan, keySpan;	

	DEBUG_ASSERT2(ctx != NULL, "Expected valid context");
	DEBUG_ASSERT2(args != NULL, "Expected valid encryption args");
	DEBUG_ASSERT2(args->version == NC_ENC_VERSION_NIP04, "Expected NIP04 encryption version");	

	ncSpanInitC(&ivSpan, args->ivData, NCEncryptionGetIvSize(args->version));
	ncSpanInitC(&keySpan, args->keyData, NC_CRYPTO_AES_KEY_SIZE);
	ncSpanInitC(&inputSpan, args->inputData, args->dataSize);
	ncSpanInit(&outputSpan, args->outputData, args->dataSize);

	/*
	 * Since were on nip-04 branch, the nonce field should always
	 * be equal to the nip04 aes iv parameter
	 */
	DEBUG_ASSERT2(ncSpanGetSizeC(ivSpan) == NIP04_IV_SIZE, "Expected valid nip04 (aes) iv size");

	/* For now just the encryption flag must be set if encryption is enabled */
	encFlags = encrypt ? NC_CRYPTO_AES_MODE_ENCRYPT : NC_CRYPTO_AES_MODE_DECRYPT;

	return ncCryptoAes256CBCUpdate(keySpan, ivSpan, inputSpan, outputSpan, encFlags) == CSTATUS_OK
		? NC_SUCCESS
		: E_OPERATION_FAILED;
}

static _nc_fn_inline cstatus_t _computeHmac(const uint8_t key[NC_HMAC_KEY_SIZE], cspan_t payload, sha256_t hmacOut)
{
	cspan_t keySpan;

	DEBUG_ASSERT2(key != NULL,		"Expected valid hmac key")
	DEBUG_ASSERT2(hmacOut != NULL,	"Expected valid hmac output buffer")

	ncSpanInitC(&keySpan, key, NC_HMAC_KEY_SIZE);

	return ncCryptoHmacSha256(keySpan, payload, hmacOut);
}

static NCResult _verifyMacEx(
	const NCContext* ctx,
	const uint8_t conversationKey[NC_CONV_KEY_SIZE],
	const NCMacVerifyArgs* args
)
{
	NCResult result;
	cspan_t payloadSpan, nonceSpan;
	sha256_t hmacOut;
	const struct nc_expand_keys* keys;
	struct message_key messageKey;
 
	DEBUG_ASSERT2(ctx != NULL, "Expected valid context")
	DEBUG_ASSERT2(conversationKey != NULL, "Expected valid conversation key")
	DEBUG_ASSERT2(args != NULL, "Expected valid mac verification args")

	/*
	* The nip44 nonce that was used for encryption must be passed to this
	* function, so it should be the same size as the nip44 iv.
	*/
	ncSpanInitC(&nonceSpan, args->nonce32, NIP44_IV_SIZE);
	ncSpanInitC(&payloadSpan, args->payload, args->payloadSize);

	/*
	* Message key is again required for the hmac verification
	*/

	if (_getMessageKey((struct conversation_key*)conversationKey, nonceSpan, &messageKey) != CSTATUS_OK)
	{
		result = E_OPERATION_FAILED;
		goto Cleanup;
	}

	/* Expand keys to get the hmac-key */
	keys = _expandKeysFromHkdf(&messageKey);

	/*
	* Compute the hmac of the data using the computed hmac key
	*/
	if (_computeHmac(keys->hmac_key, payloadSpan, hmacOut) != CSTATUS_OK)
	{
		result = E_OPERATION_FAILED;
		goto Cleanup;
	}

	/* constant time compare the macs */
	result = ncCryptoFixedTimeComp(hmacOut, args->mac32, NC_ENCRYPTION_MAC_SIZE) == 0 ? NC_SUCCESS : E_OPERATION_FAILED;

Cleanup:
	ZERO_FILL(&messageKey, sizeof(messageKey));
	ZERO_FILL(hmacOut, sizeof(hmacOut));

	return result;
}

/*
* EXTERNAL API FUNCTIONS
*/


NC_EXPORT NCResult NC_CC NCResultWithArgPosition(NCResult err, uint8_t argPosition)
{
	NCResult asPositive, argPos;

	/* Negate error code so it can be masked off*/
	asPositive = -err;
	asPositive = asPositive & NC_ERROR_CODE_MASK;

	/* Cast, and mask off and shift the argument psotion to the upper 8 bits */
	argPos = (NCResult)(argPosition) & 0xFF;
	argPos <<= NC_ARG_POSITION_OFFSET;

	return -(asPositive | argPos);
}

NC_EXPORT int NC_CC NCParseErrorCode(NCResult result, uint8_t* argPositionOut)
{
	NCResult asPositive;
	int code;

	/* convert result to a positive value*/
	asPositive = -result;

	/* Get the error code from the lower 8 bits and the argument position from the upper 8 bits*/
	code = -(asPositive & NC_ERROR_CODE_MASK);

	/* Allow argument position assignment to be null */
	if (argPositionOut) 
	{
		*argPositionOut = (asPositive >> NC_ARG_POSITION_OFFSET) & 0xFF;
	}

	return code;
}

/*	=============================
*	
*		Context functions
* 
*	============================= 
*/

NC_EXPORT uint32_t NC_CC NCGetContextStructSize(void) 
{
	return sizeof(NCContext);
}

NC_EXPORT NCContext* NC_CC NCGetSharedContext(void)
{
	/*Return the global address of the shared context structure */
	return &_ncSharedCtx;
}

NC_EXPORT NCResult NC_CC NCInitContext(
	NCContext* ctx, 
	const uint8_t entropy[NC_CONTEXT_ENTROPY_SIZE]
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_NULL_ARG(entropy, 1)

	ZERO_FILL(ctx, sizeof(NCContext));

	ctx->secpCtx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

	/* 
	* Randomize once on init, users can call reinit to 
	* randomize again as needed.
	*/
	return secp256k1_context_randomize(ctx->secpCtx, entropy) ? NC_SUCCESS : E_INVALID_ARG;
}

NC_EXPORT NCResult NC_CC NCReInitContext(
	NCContext* ctx, 
	const uint8_t entropy[NC_CONTEXT_ENTROPY_SIZE]
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_NULL_ARG(entropy, 1)
	CHECK_CONTEXT_STATE(ctx, 0)

	/* Only randomize again */
	return secp256k1_context_randomize(ctx->secpCtx, entropy) ? NC_SUCCESS : E_INVALID_ARG;
}

NC_EXPORT NCResult NC_CC NCDestroyContext(NCContext* ctx)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_CONTEXT_STATE(ctx, 0)

	/* Destroy secp256k1 context */
	secp256k1_context_destroy(ctx->secpCtx);

	/* Wipe the context */
	ZERO_FILL(ctx, sizeof(NCContext));

	return NC_SUCCESS;
}

/*	=============================
*
*		ECDSA functions
*
*	=============================
*/

NC_EXPORT NCResult NC_CC NCGetPublicKey(
	const NCContext* ctx, 
	const NCSecretKey* sk, 
	NCPublicKey* pk
)
{
	int result;
	secp256k1_keypair keyPair;
	secp256k1_xonly_pubkey xonly;

	CHECK_NULL_ARG(ctx, 0)
	CHECK_CONTEXT_STATE(ctx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(pk, 2)

	if (secp256k1_keypair_create(ctx->secpCtx, &keyPair, sk->key) != 1)
	{
		return E_INVALID_ARG;
	}

	/* Generate the x-only public key, docs say this should always return 1 */
	result = secp256k1_keypair_xonly_pub(ctx->secpCtx, &xonly, NULL, &keyPair);
	DEBUG_ASSERT2(result == 1, "Expected x-only kepair to ALWAYS return 1")

	/* Convert to compressed pubkey */
	result = _convertFromXonly(ctx, &xonly, pk);
	DEBUG_ASSERT2(result == 1, "Expected x-only pubkey serialize to return 1")

	/* Clean out keypair */
	ZERO_FILL(&keyPair, sizeof(keyPair));
	ZERO_FILL(&xonly, sizeof(xonly));

	return NC_SUCCESS;
}

NC_EXPORT NCResult NC_CC NCValidateSecretKey(const NCContext* ctx, const NCSecretKey* sk)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_CONTEXT_STATE(ctx, 0)

	/* Validate the secret key */
	return secp256k1_ec_seckey_verify(ctx->secpCtx, sk->key) == 1 
		? NC_SUCCESS 
		: E_OPERATION_FAILED;
}

/* Ecdsa Functions */

NC_EXPORT NCResult NC_CC NCSignDigest(
	const NCContext* ctx, 
	const NCSecretKey* sk, 
	const uint8_t random32[32], 
	const uint8_t digest32[32], 
	uint8_t sig64[64]
)
{
	int result;
	secp256k1_keypair keyPair;
	secp256k1_xonly_pubkey xonly;	

	/* Validate arguments */
	CHECK_NULL_ARG(ctx, 0)
	CHECK_CONTEXT_STATE(ctx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(random32, 2)
	CHECK_NULL_ARG(digest32, 3)
	CHECK_NULL_ARG(sig64, 4)

	/* Zero out the keypair and xonly structures before use */
	ZERO_FILL(&keyPair, sizeof(keyPair));
	ZERO_FILL(&xonly, sizeof(xonly));

	/* Fill keypair structure from the callers secret key */
	if (secp256k1_keypair_create(ctx->secpCtx, &keyPair, sk->key) != 1)
	{
		return E_INVALID_ARG;
	}

	/* Sign the digest */
	result = secp256k1_schnorrsig_sign32(ctx->secpCtx, sig64, digest32, &keyPair, random32);
	DEBUG_ASSERT2(result == 1, "Expected schnorr signature to return 1");

	/* x-only public key from keypair so the signature can be verified */
	result = secp256k1_keypair_xonly_pub(ctx->secpCtx, &xonly, NULL, &keyPair);
	DEBUG_ASSERT2(result == 1, "Expected x-only public key to ALWAYS return 1");

	/* Verify the signature is valid */
	result = secp256k1_schnorrsig_verify(ctx->secpCtx, sig64, digest32, 32, &xonly);
	
	ZERO_FILL(&keyPair, sizeof(keyPair));

	return result == 1 ? NC_SUCCESS : E_INVALID_ARG;
}

NC_EXPORT NCResult NC_CC NCSignData(
	const NCContext* ctx,
	const NCSecretKey* sk,
	const uint8_t random32[32],
	const uint8_t* data,
	uint32_t dataSize,
	uint8_t sig64[64]
)
{
	cspan_t dataSpan;
	sha256_t digest;	

	/* Double check is required because arg position differs */
	CHECK_NULL_ARG(ctx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(random32, 2)
	CHECK_NULL_ARG(data, 3)
	CHECK_ARG_RANGE(dataSize, 1, UINT32_MAX, 4)
	CHECK_NULL_ARG(sig64, 5)

	ncSpanInitC(&dataSpan, data, dataSize);

	/* Compute sha256 of the data before signing */
	if(ncCryptoDigestSha256(dataSpan, digest) != CSTATUS_OK)
	{
		return E_INVALID_ARG;
	}

	/* Sign the freshly computed digest */
	return NCSignDigest(ctx, sk, random32, digest, sig64);
}

NC_EXPORT NCResult NC_CC NCVerifyDigest(
	const NCContext* ctx,
	const NCPublicKey* pk,
	const uint8_t digest32[32],
	const uint8_t sig64[64]
)
{
	secp256k1_xonly_pubkey xonly;

	CHECK_NULL_ARG(ctx, 0)
	CHECK_CONTEXT_STATE(ctx, 0)
	CHECK_NULL_ARG(pk, 1)
	CHECK_NULL_ARG(digest32, 2)
	CHECK_NULL_ARG(sig64, 3)	

	ZERO_FILL(&xonly, sizeof(xonly));

	/* recover the x-only key from a compressed public key */
	if(_convertToXonly(ctx, pk, &xonly) != 1)
	{
		return E_INVALID_ARG;
	}

	return secp256k1_schnorrsig_verify(ctx->secpCtx, sig64, digest32, 32, &xonly) == 1 
		? NC_SUCCESS 
		: E_OPERATION_FAILED;
}

NC_EXPORT NCResult NC_CC NCVerifyData(
	const NCContext* ctx,
	const NCPublicKey* pk,
	const uint8_t* data,
	const uint32_t dataSize,
	const uint8_t sig64[64]
)
{
	sha256_t digest;
	cspan_t dataSpan;

	CHECK_NULL_ARG(ctx, 0)
	CHECK_NULL_ARG(pk, 1)
	CHECK_NULL_ARG(data, 2)
	CHECK_ARG_RANGE(dataSize, 1, UINT32_MAX, 3)
	CHECK_NULL_ARG(sig64, 4)

	ZERO_FILL(digest, sizeof(digest));

	ncSpanInitC(&dataSpan, data, dataSize);

	/* Compute sha256 of the data before verifying */
	if (ncCryptoDigestSha256(dataSpan, digest) != CSTATUS_OK)
	{
		return E_INVALID_ARG;
	}

	return NCVerifyDigest(ctx, pk, digest, sig64);
}

/*	=============================
*
*		ECDH functions
*
*	=============================
*/

NC_EXPORT NCResult NC_CC NCGetSharedSecret(
	const NCContext* ctx, 
	const NCSecretKey* sk, 
	const NCPublicKey* otherPk, 
	uint8_t sharedPoint[NC_SHARED_SEC_SIZE]
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_CONTEXT_STATE(ctx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(otherPk, 2)
	CHECK_NULL_ARG(sharedPoint, 3)	

	return _computeSharedSecret(ctx, sk, otherPk, (struct shared_secret*)sharedPoint);
}

NC_EXPORT NCResult NC_CC NCGetConversationKeyEx(
	const NCContext* ctx,
	const uint8_t sharedPoint[NC_SHARED_SEC_SIZE],
	uint8_t conversationKey[NC_CONV_KEY_SIZE]
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_CONTEXT_STATE(ctx, 0)
	CHECK_NULL_ARG(sharedPoint, 1)
	CHECK_NULL_ARG(conversationKey, 2)	

	/* Cast the shared point to the shared secret type */
	return _computeConversationKey(
		ctx,
		(struct shared_secret*)sharedPoint, 
		(struct conversation_key*)conversationKey
	);
}

NC_EXPORT NCResult NC_CC NCGetConversationKey(
	const NCContext* ctx,
	const NCSecretKey* sk,
	const NCPublicKey* pk,
	uint8_t conversationKey[NC_CONV_KEY_SIZE]
)
{
	NCResult result;
	struct shared_secret sharedSecret;

	CHECK_NULL_ARG(ctx, 0)
	CHECK_CONTEXT_STATE(ctx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(pk, 2)
	CHECK_NULL_ARG(conversationKey, 3)

	ZERO_FILL(&sharedSecret, sizeof(sharedSecret));

	/* Compute the shared point */
	if ((result = _computeSharedSecret(ctx, sk, pk, &sharedSecret)) != NC_SUCCESS)
	{
		goto Cleanup;
	}

	result = _computeConversationKey(ctx, &sharedSecret, (struct conversation_key*)conversationKey);

Cleanup:
	/* Clean up sensitive data */
	ZERO_FILL(&sharedSecret, sizeof(sharedSecret));

	return result;
}

NC_EXPORT NCResult NC_CC NCEncryptEx(
	const NCContext* ctx, 
	const uint8_t conversationKey[NC_CONV_KEY_SIZE], 
	NCEncryptionArgs* args
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_CONTEXT_STATE(ctx, 0)
	CHECK_NULL_ARG(conversationKey, 1)
	CHECK_NULL_ARG(args, 2)

	/* Validte ciphertext/plaintext */
	CHECK_INVALID_ARG(args->inputData, 2)
	CHECK_INVALID_ARG(args->outputData, 2)
	CHECK_INVALID_ARG(args->ivData, 2)
	CHECK_INVALID_ARG(args->keyData, 2)
	CHECK_ARG_RANGE(args->dataSize, NIP44_MIN_ENC_MESSAGE_SIZE, NIP44_MAX_ENC_MESSAGE_SIZE, 2)	

	switch (args->version) 
	{
		case NC_ENC_VERSION_NIP44:
			return _nip44CipherUpdate(
				ctx, 
				(struct conversation_key*)conversationKey,
				args,
				1 /* enables encryption mode */
			);

		case NC_ENC_VERSION_NIP04:
			/* Again, 1 enables encryption mode */
			return _nip04CipherUpdate(ctx, args, 1);

		default:
			return E_VERSION_NOT_SUPPORTED;
	}

}

NC_EXPORT NCResult NC_CC NCEncrypt(
	const NCContext* ctx, 
	const NCSecretKey* sk, 
	const NCPublicKey* pk,
	NCEncryptionArgs* args
)
{	
	NCResult result;
	struct shared_secret sharedSecret;
	struct conversation_key conversationKey;	

	CHECK_NULL_ARG(ctx, 0)
	CHECK_CONTEXT_STATE(ctx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(pk, 2)
	CHECK_NULL_ARG(args, 3)

	/* Validate input/output data */
	CHECK_INVALID_ARG(args->inputData, 3)
	CHECK_INVALID_ARG(args->outputData, 3)
	CHECK_INVALID_ARG(args->ivData, 3)

	result = E_OPERATION_FAILED;

	switch(args->version)
	{		
		case NC_ENC_VERSION_NIP44:
		{
			/* Only need zero when nip44 is used */
			ZERO_FILL(&sharedSecret, sizeof(sharedSecret));
			ZERO_FILL(&conversationKey, sizeof(conversationKey));

			/* Mac key output is only needed for nip44 */
			CHECK_INVALID_ARG(args->keyData, 3)
			CHECK_ARG_RANGE(args->dataSize, NIP44_MIN_ENC_MESSAGE_SIZE, NIP44_MAX_ENC_MESSAGE_SIZE, 3)

			/* Compute the shared point */
			if ((result = _computeSharedSecret(ctx, sk, pk, &sharedSecret)) != NC_SUCCESS)
			{
				goto Cleanup;
			}

			/* Compute the conversation key from secret and pubkic keys */
			if ((result = _computeConversationKey(ctx, &sharedSecret, &conversationKey)) != NC_SUCCESS)
			{
				goto Cleanup;
			}

			/* update the cipher in encryption mode */
			result = _nip44CipherUpdate(ctx, &conversationKey, args, 1);
		}
		break;
		
		case NC_ENC_VERSION_NIP04:
			/* Enable encryption mode */
			result = _nip04CipherUpdate(ctx, args, 1);
			break; 
			
		default:
			result = E_VERSION_NOT_SUPPORTED;
			break;
	}	

Cleanup:
	/* Clean up sensitive data */
	ZERO_FILL(&sharedSecret, sizeof(sharedSecret));
	ZERO_FILL(&conversationKey, sizeof(conversationKey));

	return result;
}

NC_EXPORT NCResult NC_CC NCDecryptEx(
	const NCContext* ctx,
	const uint8_t conversationKey[NC_CONV_KEY_SIZE],
	NCEncryptionArgs* args
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_CONTEXT_STATE(ctx, 0)
	CHECK_NULL_ARG(conversationKey, 1)
	CHECK_NULL_ARG(args, 2)

	/* Validte ciphertext/plaintext */
	CHECK_INVALID_ARG(args->inputData, 2)
	CHECK_INVALID_ARG(args->outputData, 2)
	CHECK_INVALID_ARG(args->ivData, 2)
	CHECK_ARG_RANGE(args->dataSize, NIP44_MIN_ENC_MESSAGE_SIZE, NIP44_MAX_ENC_MESSAGE_SIZE, 2)

	switch (args->version)
	{
	case NC_ENC_VERSION_NIP44:
		/* Run update in decryption mode */
		return _nip44CipherUpdate(ctx, (struct conversation_key*)conversationKey, args, 0);

	case NC_ENC_VERSION_NIP04:
		/* Run update in decryption mode */
		return _nip04CipherUpdate(ctx, args, 0);
	default:
		return E_VERSION_NOT_SUPPORTED;
	}
}

NC_EXPORT NCResult NC_CC NCDecrypt(
	const NCContext* ctx,
	const NCSecretKey* sk,
	const NCPublicKey* pk,
	NCEncryptionArgs* args
)
{
	NCResult result;
	struct shared_secret sharedSecret;
	struct conversation_key conversationKey;

	CHECK_NULL_ARG(ctx, 0)
	CHECK_CONTEXT_STATE(ctx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(pk, 2)
	CHECK_NULL_ARG(args, 3)

	/* Validte ciphertext/plaintext */
	CHECK_INVALID_ARG(args->inputData, 3)
	CHECK_INVALID_ARG(args->outputData, 3)
	CHECK_INVALID_ARG(args->ivData, 3)

	result = E_OPERATION_FAILED;

	switch (args->version)
	{
	case NC_ENC_VERSION_NIP44:
	{
		/* init structures */
		ZERO_FILL(&sharedSecret, sizeof(sharedSecret));
		ZERO_FILL(&conversationKey, sizeof(conversationKey));

		CHECK_ARG_RANGE(args->dataSize, NIP44_MIN_ENC_MESSAGE_SIZE, NIP44_MAX_ENC_MESSAGE_SIZE, 3)

		if ((result = _computeSharedSecret(ctx, sk, pk, &sharedSecret)) != NC_SUCCESS)
		{
			goto Cleanup;
		}

		if ((result = _computeConversationKey(ctx, &sharedSecret, &conversationKey)) != NC_SUCCESS)
		{
			goto Cleanup;
		}

		result = _nip44CipherUpdate(ctx, &conversationKey, args, 0);
	}
	break;

	case NC_ENC_VERSION_NIP04:		
		result = _nip04CipherUpdate(ctx, args, 0);
		break;
		
	default:
		result = E_VERSION_NOT_SUPPORTED;
		break;
	}

Cleanup:
	/* Clean up sensitive data */
	ZERO_FILL(&sharedSecret, sizeof(sharedSecret));
	ZERO_FILL(&conversationKey, sizeof(conversationKey));

	return result;
}

NC_EXPORT NCResult NC_CC NCComputeMac(
	const NCContext* ctx,
	const uint8_t hmacKey[NC_HMAC_KEY_SIZE],
	const uint8_t* payload,
	uint32_t payloadSize,
	uint8_t hmacOut[NC_ENCRYPTION_MAC_SIZE]
)
{
	cspan_t payloadSpan;

	CHECK_NULL_ARG(ctx, 0)
	CHECK_CONTEXT_STATE(ctx, 0)
	CHECK_NULL_ARG(hmacKey, 1)
	CHECK_NULL_ARG(payload, 2)
	CHECK_ARG_RANGE(payloadSize, 1, UINT32_MAX, 3)
	CHECK_NULL_ARG(hmacOut, 4)
	
	ncSpanInitC(&payloadSpan, payload, payloadSize);

	/*
	* Compute the hmac of the data using the supplied hmac key
	*/
	return _computeHmac(hmacKey, payloadSpan, hmacOut) == CSTATUS_OK 
		? NC_SUCCESS 
		: E_OPERATION_FAILED;
}


NC_EXPORT NCResult NC_CC NCVerifyMacEx(
	const NCContext* ctx,
	const uint8_t conversationKey[NC_CONV_KEY_SIZE],
	const NCMacVerifyArgs* args
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_CONTEXT_STATE(ctx, 0)
	CHECK_NULL_ARG(conversationKey, 1)
	CHECK_NULL_ARG(args, 2)

	CHECK_INVALID_ARG(args->mac32, 2)
	CHECK_INVALID_ARG(args->payload, 2)
	CHECK_INVALID_ARG(args->nonce32, 2)
	CHECK_ARG_RANGE(args->payloadSize, NIP44_MIN_ENC_MESSAGE_SIZE, NIP44_MAX_ENC_MESSAGE_SIZE, 2)	

	return _verifyMacEx(ctx, conversationKey, args);
}

NC_EXPORT NCResult NC_CC NCVerifyMac(
	const NCContext* ctx,
	const NCSecretKey* sk,
	const NCPublicKey* pk,
	const NCMacVerifyArgs* args
)
{
	NCResult result;
	struct shared_secret sharedSecret;
	struct conversation_key conversationKey;

	CHECK_NULL_ARG(ctx, 0)
	CHECK_CONTEXT_STATE(ctx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(pk, 2)
	CHECK_NULL_ARG(args, 3)

	CHECK_INVALID_ARG(args->mac32, 3)
	CHECK_INVALID_ARG(args->payload, 3)
	CHECK_INVALID_ARG(args->nonce32, 3)
	CHECK_ARG_RANGE(args->payloadSize, NIP44_MIN_ENC_MESSAGE_SIZE, NIP44_MAX_ENC_MESSAGE_SIZE, 3)

	/* init structures */
	ZERO_FILL(&sharedSecret, sizeof(sharedSecret));
	ZERO_FILL(&conversationKey, sizeof(conversationKey));

	/* Computed the shared point so we can get the converstation key */
	if ((result = _computeSharedSecret(ctx, sk, pk, &sharedSecret)) != NC_SUCCESS)
	{
		goto Cleanup;
	}

	if ((result = _computeConversationKey(ctx, &sharedSecret, &conversationKey)) != NC_SUCCESS)
	{
		goto Cleanup;
	}

	result = _verifyMacEx(ctx, conversationKey.value, args);

Cleanup:
	/* Clean up sensitive data */
	ZERO_FILL(&sharedSecret, sizeof(sharedSecret));
	ZERO_FILL(&conversationKey, sizeof(conversationKey));

	return result;
}

#define ENSURE_ENC_MODE(args, mode) if(args->version != mode) return E_VERSION_NOT_SUPPORTED;

NC_EXPORT NCResult NC_CC NCEncryptionSetPropertyEx(
	NCEncryptionArgs* args,
	uint32_t property,
	uint8_t* value,
	uint32_t valueLen
)
{
	uint32_t ivSize;

	CHECK_NULL_ARG(args, 0)
	CHECK_NULL_ARG(value, 2)

	switch (property)
	{
	case NC_ENC_SET_VERSION:

		/* Ensure version is proper length */
		CHECK_ARG_RANGE(valueLen, sizeof(uint32_t), sizeof(uint32_t), 2)

		args->version = *((uint32_t*)value);

		return NC_SUCCESS;

	case NC_ENC_SET_NIP04_KEY:
		/*
		* The AES key is stored in the hmac key field, since
		* it won't be used for the operating and should be the same size
		* as the hmac key.
		*/

		CHECK_ARG_RANGE(valueLen, NC_CRYPTO_AES_KEY_SIZE, UINT32_MAX, 3)

		ENSURE_ENC_MODE(args, NC_ENC_VERSION_NIP04)

		args->keyData = value;

		return NC_SUCCESS;

	case NC_ENC_SET_IV:
		
		ivSize = NCEncryptionGetIvSize(args->version);

		/* Gaurd invalid version */
		if (ivSize == 0)
		{
			return E_VERSION_NOT_SUPPORTED;
		}

		CHECK_ARG_RANGE(valueLen, ivSize, ivSize, 3)

		args->ivData = value;

		return NC_SUCCESS;

	case NC_ENC_SET_NIP44_MAC_KEY:

		/* The maximum size of the buffer doesn't matter as long as its larger than the key size */
		CHECK_ARG_RANGE(valueLen, NC_HMAC_KEY_SIZE, UINT32_MAX, 3)

		/* Mac key is only used in nip44 mode */
		ENSURE_ENC_MODE(args, NC_ENC_VERSION_NIP44)

		/*
		* During encryption the key data buffer is used
		* to write the hmac hey used for MAC computation
		* operations.
		*/
		args->keyData = value;

		return NC_SUCCESS;

	default:
		break;
	}

	return E_INVALID_ARG;
}

NC_EXPORT NCResult NC_CC NCEncryptionSetProperty(
	NCEncryptionArgs* args,
	uint32_t property,
	uint32_t value
)
{
	return NCEncryptionSetPropertyEx(
		args, 
		property, 
		(uint8_t*)&value, 
		sizeof(uint32_t)
	);
}

NC_EXPORT NCResult NC_CC NCEncryptionSetData(
	NCEncryptionArgs* args,
	const uint8_t* input,
	uint8_t* output,
	uint32_t dataSize
)
{
	CHECK_NULL_ARG(args, 0)
	CHECK_NULL_ARG(input, 1)
	CHECK_NULL_ARG(output, 2)
	CHECK_ARG_RANGE(dataSize, NIP44_MIN_ENC_MESSAGE_SIZE, NIP44_MAX_ENC_MESSAGE_SIZE, 3)

	args->inputData = input;
	args->outputData = output;
	args->dataSize = dataSize;

	return NC_SUCCESS;	
}

NC_EXPORT uint32_t NC_CC NCEncryptionGetIvSize(uint32_t version)
{
	switch (version)
	{
	case NC_ENC_VERSION_NIP04:
		return NIP04_IV_SIZE;

	case NC_ENC_VERSION_NIP44:
		return NIP44_IV_SIZE;

	default:
		return 0;
	}
}
