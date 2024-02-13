/*
* Copyright (c) 2024 Vaughn Nugent
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
* along with NativeHeapApi. If not, see http://www.gnu.org/licenses/.
*/

#include "noscrypt.h"

#include <secp256k1_ecdh.h>
#include <secp256k1_schnorrsig.h>

//Setup mbedtls
#include <mbedtls/platform_util.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/sha256.h>
#include <mbedtls/constant_time.h>

/* Non win platforms may need an inline override */
#if !defined(_NC_IS_WINDOWS) && !defined(inline)
	#define inline __inline__
#endif // !IS_WINDOWS

//NULL
#ifndef NULL
	#define NULL ((void*)0)
#endif // !NULL

#define CHACHA_NONCE_SIZE 12	//Size of 12 is set by the cipher spec
#define CHACHA_KEY_SIZE 32		

/*
* Local macro for secure zero buffer fill
*/
#define ZERO_FILL(x, size) mbedtls_platform_zeroize(x, size) 

//Include string for memmove
#include <string.h>
#define MEMMOV(dst, src, size) memmove(dst, src, size)

/*
* Validation macros
*/

#ifndef NC_INPUT_VALIDATION_OFF
	#define CHECK_INVALID_ARG(x, argPos) if(x == NULL) return NCResultWithArgPosition(E_INVALID_ARG, argPos);
	#define CHECK_NULL_ARG(x, argPos) if(x == NULL) return NCResultWithArgPosition(E_NULL_PTR, argPos);
	#define CHECK_ARG_RANGE(x, min, max, argPos) if(x < min || x > max) return NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, argPos);
#else
	//empty macros 
	#define CHECK_INVALID_ARG(x)
	#define CHECK_NULL_ARG(x, argPos) 
	#define CHECK_ARG_RANGE(x, min, max, argPos) 
#endif // !NC_DISABLE_INPUT_VALIDATION


#ifdef DEBUG
	/* Must include assert.h for assertions */
	#include <assert.h> 
	#define DEBUG_ASSERT(x) assert(x);
	#define DEBUG_ASSERT2(x, message) assert(x && message);
#else
	#define DEBUG_ASSERT(x)
	#define DEBUG_ASSERT2(x, message)
#endif


struct nc_expand_keys {
	uint8_t chacha_key[CHACHA_KEY_SIZE];
	uint8_t chacha_nonce[CHACHA_NONCE_SIZE];
	uint8_t hmac_key[NC_HMAC_KEY_SIZE];
};

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
* Internal helper functions to do common structure conversions
*/

static inline int _convertToXonly(const NCContext* ctx, const NCPublicKey* compressedPubKey, secp256k1_xonly_pubkey* xonly)
{
	DEBUG_ASSERT2(ctx != NULL, "Expected valid context")
	DEBUG_ASSERT2(compressedPubKey != NULL, "Expected a valid public 32byte key structure")
	DEBUG_ASSERT2(xonly != NULL, "Expected valid X-only secp256k1 public key structure ")

	//Parse the public key into the x-only structure
	return secp256k1_xonly_pubkey_parse(ctx->secpCtx, xonly, compressedPubKey->key);
}

static int _convertToPubKey(const NCContext* ctx, const NCPublicKey* compressedPubKey, secp256k1_pubkey* pubKey)
{
	int result;
	uint8_t compressed[NC_PUBKEY_SIZE + 1];

	DEBUG_ASSERT2(ctx != NULL, "Expected valid context")
	DEBUG_ASSERT2(compressedPubKey != NULL, "Expected a valid public 32byte key structure")
	DEBUG_ASSERT2(pubKey != NULL, "Expected valid secp256k1 public key structure")

	//Set the first byte to 0x02 to indicate a compressed public key
	compressed[0] = BIP340_PUBKEY_HEADER_BYTE;

	//Copy the compressed public key data into a new buffer (offset by 1 to store the header byte)
	MEMMOV((compressed + 1), compressedPubKey, sizeof(NCPublicKey));

	result = secp256k1_ec_pubkey_parse(ctx->secpCtx, pubKey, compressed, sizeof(compressed));

	//zero everything
	ZERO_FILL(compressed, sizeof(compressed));

	return result;
}

static inline int _convertFromXonly(const NCContext* ctx, const secp256k1_xonly_pubkey* xonly, NCPublicKey* compressedPubKey)
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
	((void)y32);	//unused for nostr
	((void)data);

	DEBUG_ASSERT2(output != NULL, "Expected valid output buffer")
	DEBUG_ASSERT2(x32 != NULL, "Expected a valid public 32byte x-coodinate buffer")

	//Copy the x coordinate of the shared point into the output buffer
	MEMMOV(output, x32, 32);

	return 32;	//Return the number of bytes written to the output buffer
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

	//Recover pubkey from compressed public key data
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
		(uint8_t*)sharedPoint,
		&pubKey,
		sk->key,
		&_edhHashFuncInternal,
		NULL
	);

	//Clean up sensitive data
	ZERO_FILL(&pubKey, sizeof(secp256k1_pubkey));

	//Result should be 1 on success
	return result > 0 ? NC_SUCCESS : E_OPERATION_FAILED;
}

static inline const mbedtls_md_info_t* _getSha256MdInfo(void)
{
	const mbedtls_md_info_t* info;
	//Get sha256 md info for hdkf operations
	info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	DEBUG_ASSERT2(info != NULL, "Expected SHA256 md info struct to be valid")
	return info;
}


static inline NCResult _computeConversationKey(
	const NCContext* ctx, 
	const mbedtls_md_info_t* mdInfo,
	const struct shared_secret* sharedSecret,
	struct conversation_key* ck 
)
{
	int opResult;
	//Validate internal args
	DEBUG_ASSERT2(ctx != NULL, "Expected valid context")
	DEBUG_ASSERT2(sharedSecret != NULL, "Expected a valid shared-point")
	DEBUG_ASSERT2(mdInfo != NULL, "Expected valid md context")
	DEBUG_ASSERT2(ck != NULL, "Expected a valid conversation key")
	
	//Derive the encryption key
	opResult = mbedtls_hkdf_extract(
		mdInfo,
		Nip44ConstantSalt,
		sizeof(Nip44ConstantSalt),
		(uint8_t*)sharedSecret,			//Shared secret is the input key
		NC_SHARED_SEC_SIZE,
		(uint8_t*)ck					//Output produces a conversation key
	);

	//Return success if the hkdf operation was successful
	return opResult == 0 ? NC_SUCCESS : E_OPERATION_FAILED;
}


/*
* Explode the hkdf into the chacha key, chacha nonce, and hmac key.
*/
static inline void _expandKeysFromHkdf(const struct message_key* hkdf, struct nc_expand_keys* keys)
{
	uint8_t* hkdfBytes;

	DEBUG_ASSERT2(hkdf != NULL, "Expected valid hkdf")
	DEBUG_ASSERT2(keys != NULL, "Expected valid key expand structure")

	hkdfBytes = (uint8_t*)hkdf;
	
	//Copy segments of the hkdf into the keys struct
	MEMMOV(
		keys->chacha_key, 
		hkdfBytes, 
		CHACHA_KEY_SIZE
	);

	hkdfBytes += CHACHA_KEY_SIZE;	//Offset by key size
	
	MEMMOV(
		keys->chacha_nonce, 
		hkdfBytes,
		CHACHA_NONCE_SIZE
	);

	hkdfBytes += CHACHA_NONCE_SIZE;	//Offset by nonce size

	MEMMOV(
		keys->hmac_key, 
		hkdfBytes,
		NC_HMAC_KEY_SIZE
	);
}

static int _chachaEncipher(const struct nc_expand_keys* keys, NCCryptoData* args)
{
	int result;
	mbedtls_chacha20_context chachaCtx;

	DEBUG_ASSERT2(keys != NULL, "Expected valid keys")
	DEBUG_ASSERT2(args != NULL, "Expected valid encryption args")

	//Init the chacha context
	mbedtls_chacha20_init(&chachaCtx);

	//Set the key and nonce
	result = mbedtls_chacha20_setkey(&chachaCtx, keys->chacha_key);
	DEBUG_ASSERT2(result == 0, "Expected chacha setkey to return 0")

	result = mbedtls_chacha20_starts(&chachaCtx, keys->chacha_nonce, 0);
	DEBUG_ASSERT2(result == 0, "Expected chacha starts to return 0")

	//Encrypt the plaintext
	result = mbedtls_chacha20_update(&chachaCtx, args->dataSize, args->inputData, args->outputData);
	DEBUG_ASSERT2(result == 0, "Expected chacha update to return 0")

	//Clean up the chacha context
	mbedtls_chacha20_free(&chachaCtx);

	return result;
}

static inline NCResult _getMessageKey(
	const mbedtls_md_info_t* mdInfo,
	const struct conversation_key* converstationKey, 
	const uint8_t* nonce, 
	size_t nonceSize,
	struct message_key* messageKey
)
{
	int result;
	DEBUG_ASSERT2(mdInfo != NULL, "Expected valid md context")
	DEBUG_ASSERT2(nonce != NULL, "Expected valid nonce buffer")
	DEBUG_ASSERT2(converstationKey != NULL, "Expected valid conversation key")
	DEBUG_ASSERT2(messageKey != NULL, "Expected valid message key buffer")

	//Another HKDF to derive the message key with nonce
	result = mbedtls_hkdf_expand(
		mdInfo,
		(uint8_t*)converstationKey,			//Conversation key is the input key
		NC_CONV_KEY_SIZE,
		nonce,
		nonceSize,
		(uint8_t*)messageKey,				//Output produces a message key (write it directly to struct memory)
		NC_MESSAGE_KEY_SIZE
	);

	return result == 0 ? NC_SUCCESS : E_OPERATION_FAILED;
}

static inline NCResult _encryptEx(
	const NCContext* ctx, 
	const mbedtls_md_info_t* mdINfo,
	const struct conversation_key* ck, 
	uint8_t hmacKey[NC_HMAC_KEY_SIZE],
	NCCryptoData* args
)
{
	NCResult result;
	struct message_key messageKey;
	struct nc_expand_keys cipherKeys;

	DEBUG_ASSERT2(ctx != NULL, "Expected valid context")
	DEBUG_ASSERT2(ck != NULL, "Expected valid conversation key")
	DEBUG_ASSERT2(args != NULL, "Expected valid encryption args")
	DEBUG_ASSERT2(mdINfo != NULL, "Expected valid md info struct")
	DEBUG_ASSERT2(hmacKey != NULL, "Expected valid hmac key buffer")

	//Failure, bail out
	if ((result = _getMessageKey(mdINfo, ck, args->nonce, NC_ENCRYPTION_NONCE_SIZE, &messageKey)) != NC_SUCCESS)
	{
		goto Cleanup;
	}

	//Expand the keys from the hkdf so we can use them in the cipher
	_expandKeysFromHkdf(&messageKey, &cipherKeys);

	//Copy the hmac key into the args
	MEMMOV(hmacKey, cipherKeys.hmac_key, NC_HMAC_KEY_SIZE);

	//CHACHA20
	result = _chachaEncipher(&cipherKeys, args);

Cleanup:
	//Clean up sensitive data
	ZERO_FILL(&messageKey, sizeof(messageKey));
	ZERO_FILL(&cipherKeys, sizeof(cipherKeys));

	return result;
}

static inline NCResult _decryptEx(
	const NCContext* ctx, 
	const mbedtls_md_info_t* mdInfo,
	const struct conversation_key* ck,
	NCCryptoData* args
)
{
	NCResult result;
	struct message_key messageKey;
	struct nc_expand_keys cipherKeys;

	//Assume message key buffer is the same size as the expanded key struct
	DEBUG_ASSERT2(sizeof(messageKey) == sizeof(cipherKeys), "Message key size and expanded key sizes do not match")

	DEBUG_ASSERT2(ctx != NULL, "Expected valid context")
	DEBUG_ASSERT2(ck != NULL, "Expected valid conversation key")
	DEBUG_ASSERT2(args != NULL, "Expected valid encryption args")
	DEBUG_ASSERT2(mdInfo != NULL, "Expected valid md info struct")	

	//Failure to get message keys, bail out
	if ((result = _getMessageKey(mdInfo, ck, args->nonce, NC_ENCRYPTION_NONCE_SIZE, &messageKey)) != NC_SUCCESS)
	{
		goto Cleanup;
	}

	//Expand the keys from the hkdf so we can use them in the cipher
	_expandKeysFromHkdf(&messageKey, &cipherKeys);

	//CHACHA20
	result = _chachaEncipher(&cipherKeys, args);

Cleanup:
	//Clean up sensitive data
	ZERO_FILL(&messageKey, sizeof(messageKey));

	return result;
}

/*
* EXTERNAL API FUNCTIONS
*/
NC_EXPORT uint32_t NC_CC NCGetContextStructSize(void) 
{
	return sizeof(NCContext);
}

NC_EXPORT NCResult NC_CC NCInitContext(
	NCContext* ctx, 
	const uint8_t entropy[32]
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_NULL_ARG(entropy, 1)

	ctx->secpCtx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

	//Randomize once on init
	return secp256k1_context_randomize(ctx->secpCtx, entropy) ? NC_SUCCESS : E_INVALID_ARG;
}

NC_EXPORT NCResult NC_CC NCReInitContext(
	NCContext* ctx, 
	const uint8_t entropy[32]
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_INVALID_ARG(ctx->secpCtx, 0)
	CHECK_NULL_ARG(entropy, 1)

	//Only randomize again
	return secp256k1_context_randomize(ctx->secpCtx, entropy) ? NC_SUCCESS : E_INVALID_ARG;
}

NC_EXPORT NCResult NC_CC NCDestroyContext(NCContext* ctx)
{
	CHECK_NULL_ARG(ctx, 0);
	CHECK_INVALID_ARG(ctx->secpCtx, 0);

	//Destroy secp256k1 context
	secp256k1_context_destroy(ctx->secpCtx);

	//Wipe the context
	ZERO_FILL(ctx, sizeof(NCContext));

	return NC_SUCCESS;
}

//KEY Functions
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
	CHECK_INVALID_ARG(ctx->secpCtx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(pk, 2)

	if (secp256k1_keypair_create(ctx->secpCtx, &keyPair, sk->key) != 1)
	{
		return E_INVALID_ARG;
	}

	//Generate the x-only public key, docs say this should always return 1
	result = secp256k1_keypair_xonly_pub(ctx->secpCtx, &xonly, NULL, &keyPair);
	DEBUG_ASSERT2(result == 1, "Expected x-only kepair to ALWAYS return 1")

	//Convert to compressed pubkey
	result = _convertFromXonly(ctx, &xonly, pk);
	DEBUG_ASSERT2(result == 1, "Expected x-only pubkey serialize to return 1")

	//Clean out keypair
	ZERO_FILL(&keyPair, sizeof(secp256k1_keypair));
	ZERO_FILL(&xonly, sizeof(secp256k1_xonly_pubkey));

	return NC_SUCCESS;
}

NC_EXPORT NCResult NC_CC NCValidateSecretKey(
	const NCContext* ctx, 
	const NCSecretKey* sk
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_INVALID_ARG(ctx->secpCtx, 0)

	//Validate the secret key
	return secp256k1_ec_seckey_verify(ctx->secpCtx, sk->key);
}

//Ecdsa Functions

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

	//Validate arguments
	CHECK_NULL_ARG(ctx, 0)
	CHECK_INVALID_ARG(ctx->secpCtx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(random32, 2)
	CHECK_NULL_ARG(digest32, 3)
	CHECK_NULL_ARG(sig64, 4)

	//Generate the keypair
	if (secp256k1_keypair_create(ctx->secpCtx, &keyPair, sk->key) != 1)
	{
		return E_INVALID_ARG;
	}

	//Sign the digest
	result = secp256k1_schnorrsig_sign32(ctx->secpCtx, sig64, digest32, &keyPair, random32);
	DEBUG_ASSERT2(result == 1, "Expected schnorr signature to return 1");

	//x-only public key from keypair so the signature can be verified
	result = secp256k1_keypair_xonly_pub(ctx->secpCtx, &xonly, NULL, &keyPair);
	DEBUG_ASSERT2(result == 1, "Expected x-only public key to ALWAYS return 1");

	//Verify the signature is valid
	result = secp256k1_schnorrsig_verify(ctx->secpCtx, sig64, digest32, 32, &xonly);

	//cleanup any sensitive data
	ZERO_FILL(&keyPair, sizeof(secp256k1_keypair));
	ZERO_FILL(&xonly, sizeof(secp256k1_xonly_pubkey));

	return result == 1 ? NC_SUCCESS : E_INVALID_ARG;
}

NC_EXPORT NCResult NC_CC NCSignData(
	const NCContext* ctx,
	const NCSecretKey* sk,
	const uint8_t random32[32],
	const uint8_t* data,
	size_t dataSize,
	uint8_t sig64[64]
)
{
	uint8_t digest[32];

	//Double check is required because arg position differs
	CHECK_NULL_ARG(ctx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(random32, 2)
	CHECK_NULL_ARG(data, 3)
	CHECK_ARG_RANGE(dataSize, 1, UINT32_MAX, 4)
	CHECK_NULL_ARG(sig64, 5)

	//Compute sha256 of the data before signing
	if(mbedtls_sha256(data, dataSize, digest, 0) != 0)
	{
		return E_INVALID_ARG;
	}

	//Sign the freshly computed digest
	return NCSignDigest(ctx, sk, random32, digest, sig64);
}

NC_EXPORT NCResult NC_CC NCVerifyDigest(
	const NCContext* ctx,
	const NCPublicKey* pk,
	const uint8_t digest32[32],
	const uint8_t sig64[64]
)
{
	int result;
	secp256k1_xonly_pubkey xonly;

	CHECK_NULL_ARG(ctx, 0)
	CHECK_INVALID_ARG(ctx->secpCtx, 0)
	CHECK_NULL_ARG(pk, 1)
	CHECK_NULL_ARG(digest32, 2)
	CHECK_NULL_ARG(sig64, 3)	

	//recover the x-only key from a compressed public key
	if(_convertToXonly(ctx, pk, &xonly) != 1)
	{
		return E_INVALID_ARG;
	}

	//Verify the signature
	result = secp256k1_schnorrsig_verify(ctx->secpCtx, sig64, digest32, 32, &xonly);

	//cleanup any sensitive data
	ZERO_FILL(&xonly, sizeof(secp256k1_xonly_pubkey));

	return result == 1 ? NC_SUCCESS : E_INVALID_ARG;
}

NC_EXPORT NCResult NC_CC NCVerifyData(
	const NCContext* ctx,
	const NCPublicKey* pk,
	const uint8_t* data,
	const size_t dataSize,
	const uint8_t sig64[64]
)
{
	uint8_t digest[32];

	CHECK_NULL_ARG(ctx, 0)
	CHECK_NULL_ARG(pk, 1)
	CHECK_NULL_ARG(data, 2)
	CHECK_ARG_RANGE(dataSize, 1, UINT32_MAX, 3)
	CHECK_NULL_ARG(sig64, 4)

	//Compute sha256 of the data before verifying
	if (mbedtls_sha256(data, dataSize, digest, 0) != 0)
	{
		return E_INVALID_ARG;
	}

	//Verify the freshly computed digest
	return NCVerifyDigest(ctx, pk, digest, sig64);
}

//ECDH Functions
NC_EXPORT NCResult NC_CC NCGetSharedSecret(
	const NCContext* ctx, 
	const NCSecretKey* sk, 
	const NCPublicKey* otherPk, 
	uint8_t sharedPoint[NC_SHARED_SEC_SIZE]
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_INVALID_ARG(ctx->secpCtx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(otherPk, 2)
	CHECK_NULL_ARG(sharedPoint, 3)	

	return _computeSharedSecret(
		ctx, 
		sk, 
		otherPk, 
		(struct shared_secret*)sharedPoint
	);
}

NC_EXPORT NCResult NC_CC NCGetConversationKeyEx(
	const NCContext* ctx,
	const uint8_t sharedPoint[NC_SHARED_SEC_SIZE],
	uint8_t conversationKey[NC_CONV_KEY_SIZE]
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_INVALID_ARG(ctx->secpCtx, 0)
	CHECK_NULL_ARG(sharedPoint, 1)
	CHECK_NULL_ARG(conversationKey, 2)	

	//Cast the shared point to the shared secret type
	return _computeConversationKey(
		ctx, 
		_getSha256MdInfo(),
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
	const mbedtls_md_info_t* mdInfo;

	CHECK_NULL_ARG(ctx, 0)
	CHECK_INVALID_ARG(ctx->secpCtx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(pk, 2)
	CHECK_NULL_ARG(conversationKey, 3)	
	
	mdInfo = _getSha256MdInfo();

	//Compute the shared point
	if ((result = _computeSharedSecret(ctx, sk, pk, &sharedSecret)) != NC_SUCCESS)
	{
		goto Cleanup;
	}

	result = _computeConversationKey(
		ctx, 
		mdInfo, 
		&sharedSecret, 
		(struct conversation_key*)conversationKey
	);

Cleanup:
	//Clean up sensitive data
	ZERO_FILL(&sharedSecret, sizeof(sharedSecret));

	return result;
}

NC_EXPORT NCResult NC_CC NCEncryptEx(
	const NCContext* ctx, 
	const uint8_t conversationKey[NC_CONV_KEY_SIZE], 
	uint8_t hmacKeyOut[NC_HMAC_KEY_SIZE],
	NCCryptoData* args
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_INVALID_ARG(ctx->secpCtx, 0)
	CHECK_NULL_ARG(conversationKey, 1)
	CHECK_NULL_ARG(hmacKeyOut, 2)
	CHECK_NULL_ARG(args, 3)

	//Validte ciphertext/plaintext
	CHECK_INVALID_ARG(args->inputData, 3)
	CHECK_INVALID_ARG(args->outputData, 3)
	CHECK_INVALID_ARG(args->nonce, 3)
	CHECK_ARG_RANGE(args->dataSize, NIP44_MIN_ENC_MESSAGE_SIZE, NIP44_MAX_ENC_MESSAGE_SIZE, 3)	

	return _encryptEx(
		ctx, 
		_getSha256MdInfo(), 
		(struct conversation_key*)conversationKey, 
		hmacKeyOut,
		args
	);
}

NC_EXPORT NCResult NC_CC NCEncrypt(
	const NCContext* ctx, 
	const NCSecretKey* sk, 
	const NCPublicKey* pk, 
	uint8_t hmacKeyOut[NC_HMAC_KEY_SIZE],
	NCCryptoData* args
)
{	
	NCResult result;
	const mbedtls_md_info_t* mdInfo;
	struct shared_secret sharedSecret;
	struct conversation_key conversationKey;	

	CHECK_NULL_ARG(ctx, 0)
	CHECK_INVALID_ARG(ctx->secpCtx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(pk, 2)
	CHECK_NULL_ARG(hmacKeyOut, 3)
	CHECK_NULL_ARG(args, 4)

	//Validate input/output data
	CHECK_INVALID_ARG(args->inputData, 4)
	CHECK_INVALID_ARG(args->outputData, 4)
	CHECK_INVALID_ARG(args->nonce, 4)
	CHECK_ARG_RANGE(args->dataSize, NIP44_MIN_ENC_MESSAGE_SIZE, NIP44_MAX_ENC_MESSAGE_SIZE, 4)

	mdInfo = _getSha256MdInfo();

	//Compute the shared point
	if ((result = _computeSharedSecret(ctx, sk, pk, &sharedSecret)) != NC_SUCCESS)
	{
		goto Cleanup;
	}
	
	//Compute the conversation key from secret and pubkic keys
	if ((result = _computeConversationKey(ctx, mdInfo, &sharedSecret, &conversationKey)) != NC_SUCCESS)
	{
		goto Cleanup;
	}

	result = _encryptEx(ctx, mdInfo, &conversationKey, hmacKeyOut, args);

Cleanup:
	//Clean up sensitive data
	ZERO_FILL(&sharedSecret, sizeof(sharedSecret));
	ZERO_FILL(&conversationKey, sizeof(conversationKey));

	return result;
}

NC_EXPORT NCResult NC_CC NCDecryptEx(
	const NCContext* ctx, 
	const uint8_t conversationKey[NC_CONV_KEY_SIZE], 
	NCCryptoData* args
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_INVALID_ARG(ctx->secpCtx, 0)
	CHECK_NULL_ARG(conversationKey, 1)
	CHECK_NULL_ARG(args, 2)

	//Validte ciphertext/plaintext
	CHECK_INVALID_ARG(args->inputData, 2)
	CHECK_INVALID_ARG(args->outputData, 2)
	CHECK_INVALID_ARG(args->nonce, 2)
	CHECK_ARG_RANGE(args->dataSize, NIP44_MIN_ENC_MESSAGE_SIZE, NIP44_MAX_ENC_MESSAGE_SIZE, 2)

	return _decryptEx(
		ctx, 
		_getSha256MdInfo(), 
		(struct conversation_key*)conversationKey, 
		args
	);
}

NC_EXPORT NCResult NC_CC NCDecrypt(
	const NCContext* ctx,
	const NCSecretKey* sk,
	const NCPublicKey* pk,
	NCCryptoData* args
)
{
	NCResult result;
	struct shared_secret sharedSecret;
	struct conversation_key conversationKey;
	const mbedtls_md_info_t* mdInfo;

	CHECK_NULL_ARG(ctx, 0)
	CHECK_INVALID_ARG(ctx->secpCtx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(pk, 2)
	CHECK_NULL_ARG(args, 3)

	//Validte ciphertext/plaintext
	CHECK_INVALID_ARG(args->inputData, 3)
	CHECK_INVALID_ARG(args->outputData, 3)
	CHECK_INVALID_ARG(args->nonce, 3)
	CHECK_ARG_RANGE(args->dataSize, NIP44_MIN_ENC_MESSAGE_SIZE, NIP44_MAX_ENC_MESSAGE_SIZE, 3)

	mdInfo = _getSha256MdInfo();

	if ((result = _computeSharedSecret(ctx, sk, pk, &sharedSecret)) != NC_SUCCESS)
	{
		goto Cleanup;
	}

	if ((result = _computeConversationKey(ctx, mdInfo, &sharedSecret, &conversationKey)) != NC_SUCCESS)
	{
		goto Cleanup;
	}

	result = _decryptEx(ctx, mdInfo, &conversationKey, args);

Cleanup:
	//Clean up sensitive data
	ZERO_FILL(&sharedSecret, sizeof(sharedSecret));
	ZERO_FILL(&conversationKey, sizeof(conversationKey));

	return result;
}

NC_EXPORT NCResult NCComputeMac(
	const NCContext* ctx,
	const uint8_t hmacKey[NC_HMAC_KEY_SIZE],
	const uint8_t* payload,
	size_t payloadSize,
	uint8_t hmacOut[NC_ENCRYPTION_MAC_SIZE]
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_INVALID_ARG(ctx->secpCtx, 0)
	CHECK_NULL_ARG(hmacKey, 1)
	CHECK_NULL_ARG(payload, 2)
	CHECK_ARG_RANGE(payloadSize, 1, UINT32_MAX, 3)
	CHECK_NULL_ARG(hmacOut, 4)

	/*
	* Compute the hmac of the data using the supplied hmac key
	*/
	return mbedtls_md_hmac(
		_getSha256MdInfo(), 
		hmacKey, 
		NC_HMAC_KEY_SIZE, 
		payload, 
		payloadSize, 
		hmacOut
	) == 0 ? NC_SUCCESS : E_OPERATION_FAILED;
}

NC_EXPORT NCResult NC_CC NCVerifyMacEx(
	const NCContext* ctx,
	const uint8_t conversationKey[NC_CONV_KEY_SIZE],
	NCMacVerifyArgs* args
)
{
	NCResult result;
	const mbedtls_md_info_t* sha256Info;
	struct message_key messageKey;
	struct nc_expand_keys keys;
	uint8_t hmacOut[NC_ENCRYPTION_MAC_SIZE];

	CHECK_NULL_ARG(ctx, 0)
	CHECK_INVALID_ARG(ctx->secpCtx, 0)
	CHECK_NULL_ARG(conversationKey, 1)
	CHECK_NULL_ARG(args, 2)

	CHECK_INVALID_ARG(args->mac, 2)
	CHECK_INVALID_ARG(args->payload, 2)
	CHECK_INVALID_ARG(args->nonce, 2)
	CHECK_ARG_RANGE(args->payloadSize, NIP44_MIN_ENC_MESSAGE_SIZE, NIP44_MAX_ENC_MESSAGE_SIZE, 2)

	sha256Info = _getSha256MdInfo();

	/*
	* We need to get the message key in order to 
	* get the required hmac key
	*/
	result = _getMessageKey(
		sha256Info,
		(struct conversation_key*)conversationKey,
		args->nonce,
		NC_ENCRYPTION_NONCE_SIZE,
		&messageKey
	);

	if(result != NC_SUCCESS)
	{
		goto Cleanup;
	}

	/* Expand keys to get the hmac-key */
	_expandKeysFromHkdf(&messageKey, &keys);

	/*
	* Compute the hmac of the data using the computed hmac key
	*/
	if(mbedtls_md_hmac(sha256Info, keys.hmac_key, NC_HMAC_KEY_SIZE, args->payload, args->payloadSize, hmacOut) != 0)
	{
		result = E_OPERATION_FAILED;
		goto Cleanup;
	}

	/* constant time compare the macs */
	result = mbedtls_ct_memcmp(hmacOut, args->mac, NC_ENCRYPTION_MAC_SIZE) == 0 ? NC_SUCCESS : E_OPERATION_FAILED;

Cleanup:
	/* Clean up sensitive data */
	ZERO_FILL(&messageKey, sizeof(messageKey));
	ZERO_FILL(&keys, sizeof(keys));
	ZERO_FILL(hmacOut, NC_ENCRYPTION_MAC_SIZE);

	return result;
}

NC_EXPORT NCResult NC_CC NCVerifyMac(
	const NCContext* ctx,
	const NCSecretKey* sk,
	const NCPublicKey* pk,
	NCMacVerifyArgs* args
)
{
	CHECK_NULL_ARG(ctx, 0)
	CHECK_INVALID_ARG(ctx->secpCtx, 0)
	CHECK_NULL_ARG(sk, 1)
	CHECK_NULL_ARG(pk, 2)
	CHECK_NULL_ARG(args, 3)

	NCResult result;
	struct shared_secret sharedSecret;
	struct conversation_key conversationKey;

	/* Computed the shared point so we can get the converstation key */
	if ((result = _computeSharedSecret(ctx, sk, pk, &sharedSecret)) != NC_SUCCESS)
	{
		goto Cleanup;
	}

	if ((result = _computeConversationKey(ctx, _getSha256MdInfo(), &sharedSecret, &conversationKey)) != NC_SUCCESS)
	{
		goto Cleanup;
	}

	result = NCVerifyMacEx(ctx, (uint8_t*)&conversationKey, args);

Cleanup:
	/* Clean up sensitive data */
	ZERO_FILL(&sharedSecret, sizeof(sharedSecret));
	ZERO_FILL(&conversationKey, sizeof(conversationKey));

	return result;
}