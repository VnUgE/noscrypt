/*
* Copyright (c) 2025 Vaughn Nugent
*
* Package: noscrypt
* File: nc-util-test.c
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

/*      TEST CONSTANTS     */

#define NC_TEST_NIP04_IV_SIZE	0x10   /* Spec defines nip04 nonce (iv) size must be 16 bytes */
#define NC_TEST_NIP44_IV_SIZE	0x20   /* Spec defines nip44 nonce (iv) size must be 32 bytes */

#define NC_TEST_ENTRY TestUtilFunctions
#define HEX_BYTE_LIST_SIZE 25

#include "test.h"
#include <noscryptutil.h>

static int TestUtilNip44Encryption(
    const NCContext* libCtx, 
    span_t sendKey, 
    span_t recvKey, 
    span_t nonce, 
    span_t expected,
    span_t plainText
)
{
    NCPublicKey recvPubKey;
    uint8_t* outData;

    ENSURE(NCValidateSecretKey(libCtx, NCByteCastToSecretKey(sendKey.data)) == NC_SUCCESS);
    ENSURE(NCGetPublicKey(libCtx, NCByteCastToSecretKey(recvKey.data), &recvPubKey) == NC_SUCCESS);

    /* Alloc cipher in nip44 encryption mode */
    NCUtilCipherContext* ctx = NCUtilCipherAlloc(
        NC_ENC_VERSION_NIP44, 
        NC_UTIL_CIPHER_MODE_ENCRYPT | NC_UTIL_CIPHER_ZERO_ON_FREE
    );
    
    ENSURE(ctx != NULL);

    TEST(ncSpanGetSize(nonce), (uint32_t)NCUtilCipherGetIvSize(ctx));

    TEST(NCUtilCipherInit(ctx, plainText.data, plainText.size), NC_SUCCESS);

    /* Nonce is required for nip44 encryption */
    TEST(NCUtilCipherSetProperty(ctx, NC_ENC_SET_IV, nonce.data, nonce.size), NC_SUCCESS);

    /* Cipher update should return the  */
    TEST(NCUtilCipherUpdate(ctx, libCtx, NCByteCastToSecretKey(sendKey.data), &recvPubKey), NC_SUCCESS);

    NCResult cipherOutputSize = NCUtilCipherGetOutputSize(ctx);

    TEST(cipherOutputSize, expected.size);

    outData = (uint8_t*)malloc(cipherOutputSize);
    TASSERT(outData != NULL);

    /* Read the encrypted payload to test */
    TEST(NCUtilCipherReadOutput(ctx, outData, (uint32_t)cipherOutputSize), cipherOutputSize);

    /* Ensure encrypted payload matches */
    TEST(memcmp(outData, expected.data, cipherOutputSize), 0);

    free(outData);

    /* Free encryption memory */
    NCUtilCipherFree(ctx);

    return 0;
}

static int TestUtilNip44Decryption(
    const NCContext* libCtx,
    span_t sendKey,
    span_t recvKey,
    span_t payload,
	span_t expectedPt
)
{
    NCPublicKey recvPubKey;
    uint8_t* outData;

    ENSURE(NCValidateSecretKey(libCtx, NCByteCastToSecretKey(sendKey.data)) == NC_SUCCESS);
    ENSURE(NCGetPublicKey(libCtx, NCByteCastToSecretKey(recvKey.data), &recvPubKey) == NC_SUCCESS);

    /* Alloc cipher in nip44 decryption mode */
    NCUtilCipherContext* ctx = NCUtilCipherAlloc(
        NC_ENC_VERSION_NIP44,
        NC_UTIL_CIPHER_MODE_DECRYPT | NC_UTIL_CIPHER_ZERO_ON_FREE
    );

    ENSURE(ctx != NULL);

    /* submit encrypted payload for ciphertext */
    TEST(NCUtilCipherInit(ctx, payload.data, payload.size), NC_SUCCESS);

    TEST(NCUtilCipherUpdate(ctx, libCtx, NCByteCastToSecretKey(sendKey.data), &recvPubKey), NC_SUCCESS);

    NCResult plaintextSize = NCUtilCipherGetOutputSize(ctx);

    TEST(plaintextSize, expectedPt.size);

    outData = (uint8_t*)malloc(plaintextSize);

    TASSERT(outData != NULL);

    /* Read the encrypted payload to test */
    TEST(NCUtilCipherReadOutput(ctx, outData, (uint32_t)plaintextSize), plaintextSize);

    /* Ensure encrypted payload matches */
    TEST(memcmp(outData, expectedPt.data, plaintextSize), 0);

    free(outData);

    /* Free encryption memory */
    NCUtilCipherFree(ctx);

    return 0;
}

/* Padding tests taken from the nip44 repo vectors.json file */
static const uint32_t _nip44PadTestActual[23] = { 16, 32, 33, 37, 45, 49, 64, 65, 100, 111, 200, 250, 320, 383, 384, 400, 500, 512, 515, 700, 800, 900,  1020 };
static const uint32_t _nip44PadTestExpected[23] = { 32, 32, 64, 64, 64, 64, 64, 96, 128, 128, 224, 256, 320, 384, 384, 448, 512, 512, 640, 768, 896, 1024, 1024 };

/* Padding should be a multiple of the aes block size */
static const uint32_t _nip04PadTestActual[9] = { 5, 15, 32, 33, 37, 45, 49, 255, 1024 };
static const uint32_t _nip04PadTestExpected[9] = { 16, 16, 48, 48, 48, 48, 64, 256, 1040 };

static int TestNip44Encryption(void)
{
    /* From the nip44 vectors file */
    span_t sendKey = FromHexString("0000000000000000000000000000000000000000000000000000000000000001", sizeof(NCSecretKey));
    span_t recvKey = FromHexString("0000000000000000000000000000000000000000000000000000000000000002", sizeof(NCSecretKey));
    span_t nonce = FromHexString("0000000000000000000000000000000000000000000000000000000000000001", NC_TEST_NIP44_IV_SIZE);
    span_t payload = FromHexString("02000000000000000000000000000000000000000000000000000000000000000179ed06e5548ad3ff58ca920e6c0b4329f6040230f7e6e5641f20741780f0adc35a09794259929a02bb06ad8e8cf709ee4ccc567e9d514cdf5781af27a3e905e55b1b", 99);
    span_t plainText = FromHexString("61", 1);

    return TestUtilNip44Encryption(TestContext, sendKey, recvKey, nonce, payload, plainText);
}

static int TestNip44Decryption(void)
{
    /* From the nip44 vectors file */
    span_t sendKey = FromHexString("0000000000000000000000000000000000000000000000000000000000000001", sizeof(NCSecretKey));
    span_t recvKey = FromHexString("0000000000000000000000000000000000000000000000000000000000000002", sizeof(NCSecretKey));
    span_t payload = FromHexString("02000000000000000000000000000000000000000000000000000000000000000179ed06e5548ad3ff58ca920e6c0b4329f6040230f7e6e5641f20741780f0adc35a09794259929a02bb06ad8e8cf709ee4ccc567e9d514cdf5781af27a3e905e55b1b", 99);
    span_t plainText = FromHexString("61", 1);

    return TestUtilNip44Decryption(TestContext, sendKey, recvKey, payload, plainText);
}

static int TestPadding(void)
{
    for (int i = 0; i < 23; i++)
    {
        int32_t totalSize = _nip44PadTestExpected[i] + 67;

        TEST(NCUtilGetEncryptionPaddedSize(NC_ENC_VERSION_NIP44, _nip44PadTestActual[i]), _nip44PadTestExpected[i]);
        TEST(NCUtilGetEncryptionBufferSize(NC_ENC_VERSION_NIP44, _nip44PadTestActual[i]), totalSize);
    }

    for (int i = 0; i < 9; i++)
    {
        TEST(NCUtilGetEncryptionPaddedSize(NC_ENC_VERSION_NIP04, _nip04PadTestActual[i]), _nip04PadTestExpected[i]);
        TEST(NCUtilGetEncryptionBufferSize(NC_ENC_VERSION_NIP04, _nip04PadTestActual[i]), _nip04PadTestExpected[i]);
    }

    return 0;
}

static int TestUtilFunctions(void)
{
    PRINTL("TEST: Util functions");

	RUN_TEST(TestPadding());

    /*
    * NOTE:
    * https://github.com/paulmillr/nip44/issues/21
    * 
    * 65536 is not allowed for nip44 plaintext size, however it is a valid input 
    * for padding. It is assumed that the buffer calculation function will detect
	* these valid inputs and return an error, but the padding calculation will not.
    */
    TEST(NCUtilGetEncryptionPaddedSize(NC_ENC_VERSION_NIP44, 65536u), 65536u);
    TEST(NCUtilGetEncryptionBufferSize(NC_ENC_VERSION_NIP44, 65536u), ARG_RANGE_ERROR_POS_1);

    /* Again, zero is not a valid buffer size, but is valid for padding */
    TEST(NCUtilGetEncryptionPaddedSize(NC_ENC_VERSION_NIP44, 0u), 0x20u);
    TEST(NCUtilGetEncryptionBufferSize(NC_ENC_VERSION_NIP44, 0u), ARG_RANGE_ERROR_POS_1);

    RUN_TEST(TestNip44Encryption());

    RUN_TEST(TestNip44Decryption());

	return 0;
}
