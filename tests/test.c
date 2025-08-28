/*
* Copyright (c) 2025 Vaughn Nugent
*
* Package: noscrypt
* File: test.c
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

#define NC_TEST_ENTRY RunTests
#define HEX_BYTE_LIST_SIZE 16

#include "test.h"


/*      TEST CONSTANTS     */

#define NC_TEST_NIP04_IV_SIZE	0x10   /* Spec defines nip04 nonce (iv) size must be 16 bytes */
#define NC_TEST_NIP44_IV_SIZE	0x20   /* Spec defines nip44 nonce (iv) size must be 32 bytes */

static const uint8_t zero32[32] = { 0 };

static const char* message = "Test message to sign";

static int InitKepair(NCSecretKey* secKey, NCPublicKey* pubKey)
{
    /* Get random private key */
    FillRandomData(secKey, sizeof(NCSecretKey));

    /* Ensure not empty */
    ENSURE(memcmp(zero32, secKey, 32) != 0);

    /* Ensure the key is valid, result should be 1 on success */
    TEST(NCValidateSecretKey(TestContext, secKey), NC_SUCCESS);

    /* Generate a public key from the secret key */
    TEST(NCGetPublicKey(TestContext, secKey, pubKey), NC_SUCCESS);

    return 0;
}

static int TestEcdsa(NCSecretKey* secKey, NCPublicKey* pubKey)
{ 
   
    uint8_t sigEntropy[32];
    uint8_t invalidSig[64];
    span_t digestHex;

    /*Init a new secret key with random data */
    FillRandomData(invalidSig, sizeof(invalidSig));
    FillRandomData(sigEntropy, sizeof(sigEntropy));

    /* This is the sha256 digest of the message charater buffer above */
    digestHex = FromHexString("58884db8f9b2d5583a54b44daeccf029af4dd2874aa5e3dc0e55febebab55d18", 32);

    /* Test signing just the message digest */
    {
		uint8_t sig[64];
        TEST(NCSignDigest(TestContext, secKey, sigEntropy, digestHex.data, sig), NC_SUCCESS);
        TEST(NCVerifyDigest(TestContext, pubKey, digestHex.data, sig), NC_SUCCESS);
    }
    
    /* Sign and verify the raw message */
    {
        uint8_t sig[64];
        TEST(NCSignData(TestContext, secKey, sigEntropy, (uint8_t*)message, strlen32(message), sig), NC_SUCCESS);
        TEST(NCVerifyData(TestContext, pubKey, (uint8_t*)message, strlen32(message), sig), NC_SUCCESS);
    }

    /* Tests that signing the message and it's digest result in the same signature */
	{
		uint8_t sig1[64];
		uint8_t sig2[64];

        /* Ensure operations succeed but dont print them as test cases */
        ENSURE(NCSignData(TestContext, secKey, sigEntropy, (uint8_t*)message, strlen32(message), sig1) == NC_SUCCESS);
        ENSURE(NCSignDigest(TestContext, secKey, sigEntropy, digestHex.data, sig2) == NC_SUCCESS);
		
        /* Perform test */
        TEST(memcmp(sig1, sig2, 64), 0);
	}

    /* Checks that the signature raw message can be verified against the digest of the message */
    {
        uint8_t sig[64];
		
        ENSURE(NCSignData(TestContext, secKey, sigEntropy, (uint8_t*)message, strlen32(message), sig) == NC_SUCCESS);
        TEST(NCVerifyDigest(TestContext, pubKey, digestHex.data, sig), NC_SUCCESS);

        /* Now invert test, zero signature to ensure its overwritten */
        ZERO_FILL(sig, sizeof(sig));

        ENSURE(NCSignDigest(TestContext, secKey, sigEntropy, digestHex.data, sig) == NC_SUCCESS);
        TEST(NCVerifyData(TestContext, pubKey, (uint8_t*)message, strlen32(message), sig), NC_SUCCESS);
	}

    /* test verification of invalid signature */
    {
        TEST(NCVerifyDigest(TestContext, pubKey, digestHex.data, invalidSig), E_OPERATION_FAILED);
    }

	return 0;
}

#ifndef NC_INPUT_VALIDATION_OFF

static int TestPublicApiArgumentValidation()
{
    NCContext* ctx;
    uint8_t ctxRandom[32];
    uint8_t sig64[64];
    NCSecretKey secKey;
    NCPublicKey pubKey;
    uint8_t hmacKeyOut[NC_HMAC_KEY_SIZE];
    uint8_t iv[NC_TEST_NIP44_IV_SIZE];
   
    NCEncryptionArgs cryptoData;

    /* Zero fill the structure to inialize */
    ZERO_FILL(&cryptoData, sizeof(cryptoData));

    {
        TEST(NCEncryptionGetIvSize(NC_ENC_VERSION_NIP44), sizeof(iv));
        TEST(NCEncryptionGetIvSize(NC_ENC_VERSION_NIP44), NC_TEST_NIP44_IV_SIZE);
        TEST(NCEncryptionGetIvSize(NC_ENC_VERSION_NIP04), NC_TEST_NIP04_IV_SIZE);

        /*
        * Test arguments for encryption properties
        */

		uint8_t testBuff32[32];

		TEST(NCEncryptionSetProperty(NULL, NC_ENC_SET_VERSION, NC_ENC_VERSION_NIP04), ARG_ERROR_POS_0)
		TEST(NCEncryptionSetProperty(&cryptoData, 0, 1), E_INVALID_ARG)

        TEST(NCEncryptionSetData(NULL, zero32, sig64, sizeof(zero32)), ARG_ERROR_POS_0)
		TEST(NCEncryptionSetData(&cryptoData, NULL, sig64, sizeof(zero32)), ARG_ERROR_POS_1)
		TEST(NCEncryptionSetData(&cryptoData, zero32, NULL, sizeof(zero32)), ARG_ERROR_POS_2)
		TEST(NCEncryptionSetData(&cryptoData, zero32, sig64, 0), ARG_RANGE_ERROR_POS_3)

        /* Setting the IV should fail because a version is not set*/
        TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, iv, sizeof(iv)), E_VERSION_NOT_SUPPORTED);

        /* Set to nip44 to continue nip44 tests */
        TEST(NCEncryptionSetProperty(&cryptoData, NC_ENC_SET_VERSION, NC_ENC_VERSION_NIP44), NC_SUCCESS)

		TEST(NCEncryptionSetPropertyEx(&cryptoData, 0, iv, sizeof(iv)), E_INVALID_ARG)
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, NULL, sizeof(iv)), ARG_ERROR_POS_2)
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, iv, 0), ARG_RANGE_ERROR_POS_3)
		/* Nonce size should fail if not exactly the required iv size */
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, iv, NC_TEST_NIP44_IV_SIZE - 1), ARG_RANGE_ERROR_POS_3)
        TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, iv, NC_TEST_NIP44_IV_SIZE + 1), ARG_RANGE_ERROR_POS_3)

		TEST(NCEncryptionSetPropertyEx(&cryptoData, 0, hmacKeyOut, sizeof(hmacKeyOut)), E_INVALID_ARG)
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP44_MAC_KEY, NULL, sizeof(hmacKeyOut)), ARG_ERROR_POS_2)
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP44_MAC_KEY, hmacKeyOut, 0), ARG_RANGE_ERROR_POS_3)
        /* Key size should fail if smaller than the required nip44 key size */
        TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP44_MAC_KEY, hmacKeyOut, NC_HMAC_KEY_SIZE - 1), ARG_RANGE_ERROR_POS_3) 

		
        /* Test for nip04 */
        
        /* Any nip04 specific properties should fail since nip44 has already been set */
		
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP04_KEY, testBuff32, sizeof(testBuff32)), E_VERSION_NOT_SUPPORTED)

		/* Set to nip04 to continue nip04 tests */
		ENSURE(NCEncryptionSetProperty(&cryptoData, NC_ENC_SET_VERSION, NC_ENC_VERSION_NIP04) == NC_SUCCESS)

		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, NULL, sizeof(testBuff32)), ARG_ERROR_POS_2)
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, testBuff32, 0), ARG_RANGE_ERROR_POS_3)
        /* IV size should fail if not exact size IV for the version */
        TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, testBuff32, NC_TEST_NIP04_IV_SIZE - 1), ARG_RANGE_ERROR_POS_3)
        TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, testBuff32, NC_TEST_NIP04_IV_SIZE + 1), ARG_RANGE_ERROR_POS_3)


		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP04_KEY, NULL, sizeof(testBuff32)), ARG_ERROR_POS_2)
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP04_KEY, testBuff32, 0), ARG_RANGE_ERROR_POS_3)
		/* Key size should fail if smaller than the required nip04 key size */
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP04_KEY, testBuff32, NC_NIP04_KEY_SIZE - 1), ARG_RANGE_ERROR_POS_3)
    }

    /* Prep the crypto structure for proper usage */
	ENSURE(NCEncryptionSetProperty(&cryptoData, NC_ENC_SET_VERSION, NC_ENC_VERSION_NIP44) == NC_SUCCESS);
    ENSURE(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, iv, sizeof(iv)) == NC_SUCCESS);
    ENSURE(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP44_MAC_KEY, hmacKeyOut, sizeof(hmacKeyOut)) == NC_SUCCESS);
	
    /* Assign the encryption material */
    ENSURE(NCEncryptionSetData(&cryptoData, zero32, sig64, sizeof(zero32)) == NC_SUCCESS);


    FillRandomData(ctxRandom, 32);
    FillRandomData(iv, sizeof(iv));

    /*
    * Alloc context structure on the heap before use. 
    * THIS WILL LEAK IN THE CURRENT CONFIG ALWAYS FREE UNDER NORMAL CONDITIONS 
    */

#ifdef NOSCRYPTUTIL_H
    ctx = NCUtilContextAlloc();
#else
    ctx = (NCContext*)malloc(NCGetContextStructSize());
#endif

    TASSERT(ctx != NULL)

    /*Test null context*/
    TEST(NCInitContext(NULL, ctxRandom),    ARG_ERROR_POS_0)
    TEST(NCInitContext(ctx, NULL),         ARG_ERROR_POS_1)

    /* actually init a context to perform tests */
    TASSERT(NCInitContext(ctx, ctxRandom) == NC_SUCCESS);

    /*
    * Test null context
    * NOTE: This is never freed, this shouldnt be an issue 
    * for testing, but this will leak memory. (libsecp256k2 
    * allocates internally)
    */
    TEST(NCDestroyContext(NULL), ARG_ERROR_POS_0)

    /*reinit*/
    TEST(NCReInitContext(NULL, ctxRandom),      ARG_ERROR_POS_0)
    TEST(NCReInitContext(ctx, NULL),            ARG_ERROR_POS_1)

    /*Test null secret key*/
    TEST(NCGetPublicKey(ctx, NULL, &pubKey),    ARG_ERROR_POS_1)
    TEST(NCGetPublicKey(ctx, &secKey, NULL),    ARG_ERROR_POS_2)

    /*Test null secret key*/
    TEST(NCValidateSecretKey(NULL, &secKey),    ARG_ERROR_POS_0)
    TEST(NCValidateSecretKey(ctx, NULL),        ARG_ERROR_POS_1)
    /* Should fail with a zero key */
	TEST(NCValidateSecretKey(ctx, NCByteCastToSecretKey(zero32)), E_OPERATION_FAILED)

    /*Verify sig64 args test*/
    TEST(NCVerifyDigest(NULL, &pubKey, zero32, sig64),     ARG_ERROR_POS_0)
    TEST(NCVerifyDigest(ctx, NULL, zero32, sig64),         ARG_ERROR_POS_1)
    TEST(NCVerifyDigest(ctx, &pubKey, NULL, sig64),        ARG_ERROR_POS_2)
    TEST(NCVerifyDigest(ctx, &pubKey, zero32, NULL),       ARG_ERROR_POS_3)

    /*Test verify data args*/
    TEST(NCVerifyData(NULL, &pubKey, zero32, 32, sig64),   ARG_ERROR_POS_0)
    TEST(NCVerifyData(ctx, NULL, zero32, 32, sig64),       ARG_ERROR_POS_1)
    TEST(NCVerifyData(ctx, &pubKey, NULL, 32, sig64),      ARG_ERROR_POS_2)
    TEST(NCVerifyData(ctx, &pubKey, zero32, 0, sig64),     ARG_RANGE_ERROR_POS_3)
    TEST(NCVerifyData(ctx, &pubKey, zero32, 32, NULL),     ARG_ERROR_POS_4)

    /*Test null sign data args*/
    TEST(NCSignData(NULL, &secKey, zero32, zero32, 32, sig64),  ARG_ERROR_POS_0)
    TEST(NCSignData(ctx, NULL, zero32, zero32, 32, sig64),      ARG_ERROR_POS_1)
    TEST(NCSignData(ctx, &secKey, NULL, zero32, 32, sig64),     ARG_ERROR_POS_2)
    TEST(NCSignData(ctx, &secKey, zero32, NULL, 32, sig64),     ARG_ERROR_POS_3)
    TEST(NCSignData(ctx, &secKey, zero32, zero32, 0, sig64),    ARG_RANGE_ERROR_POS_4)
    TEST(NCSignData(ctx, &secKey, zero32, zero32, 32, NULL),    ARG_ERROR_POS_5)
   
    /*Test null sign digest args*/
    TEST(NCSignDigest(NULL, &secKey, zero32, zero32, sig64),    ARG_ERROR_POS_0)
    TEST(NCSignDigest(ctx, NULL, zero32, zero32, sig64),        ARG_ERROR_POS_1)
    TEST(NCSignDigest(ctx, &secKey, NULL, zero32, sig64),       ARG_ERROR_POS_2)
	TEST(NCSignDigest(ctx, &secKey, zero32, NULL, sig64),       ARG_ERROR_POS_3)
    TEST(NCSignDigest(ctx, &secKey, zero32, zero32, NULL),      ARG_ERROR_POS_4)

    /*Test null encrypt args*/
    TEST(NCEncrypt(NULL, &secKey, &pubKey, &cryptoData),    ARG_ERROR_POS_0)
    TEST(NCEncrypt(ctx, NULL, &pubKey, &cryptoData),        ARG_ERROR_POS_1)
	TEST(NCEncrypt(ctx, &secKey, NULL, &cryptoData),        ARG_ERROR_POS_2)
    TEST(NCEncrypt(ctx, &secKey, &pubKey, NULL),            ARG_ERROR_POS_3)

    /*Test invalid data size*/
    cryptoData.dataSize = 0;
    TEST(NCEncrypt(ctx, &secKey, &pubKey, &cryptoData), ARG_RANGE_ERROR_POS_3)
    
    /*Test null input data */
    cryptoData.dataSize = 32;
    cryptoData.inputData = NULL;
	TEST(NCEncrypt(ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)

    /*Test null output data */
	cryptoData.inputData = zero32;
    cryptoData.outputData = NULL;
	TEST(NCEncrypt(ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)

    /* Decrypt */
    cryptoData.dataSize = 32;
    cryptoData.inputData = zero32;
    cryptoData.outputData = sig64;

    TEST(NCDecrypt(NULL, &secKey, &pubKey, &cryptoData),    ARG_ERROR_POS_0)
    TEST(NCDecrypt(ctx, NULL, &pubKey, &cryptoData),       ARG_ERROR_POS_1)
	TEST(NCDecrypt(ctx, &secKey, NULL, &cryptoData),       ARG_ERROR_POS_2)
    TEST(NCDecrypt(ctx, &secKey, &pubKey, NULL),           ARG_ERROR_POS_3)

    /* Test invalid data size */
	cryptoData.dataSize = 0;
    TEST(NCDecrypt(ctx, &secKey, &pubKey, &cryptoData), ARG_RANGE_ERROR_POS_3)

    /* Test null input data */
	cryptoData.dataSize = 32;
    cryptoData.inputData = NULL;
	TEST(NCDecrypt(ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)

    /*Test null output data */
    cryptoData.inputData = zero32;
    cryptoData.outputData = NULL;
    TEST(NCDecrypt(ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)
    
    {
        uint8_t hmacDataOut[NC_ENCRYPTION_MAC_SIZE];
        TEST(NCComputeMac(NULL, hmacKeyOut, zero32, 32, hmacDataOut),   ARG_ERROR_POS_0)
        TEST(NCComputeMac(ctx, NULL, zero32, 32, hmacDataOut),         ARG_ERROR_POS_1)
        TEST(NCComputeMac(ctx, hmacKeyOut, NULL, 32, hmacDataOut),     ARG_ERROR_POS_2)
        TEST(NCComputeMac(ctx, hmacKeyOut, zero32, 0, hmacDataOut),    ARG_RANGE_ERROR_POS_3)
        TEST(NCComputeMac(ctx, hmacKeyOut, zero32, 32, NULL),          ARG_ERROR_POS_4)
    }

    {
        NCMacVerifyArgs macArgs;
        macArgs.payload = zero32;
        macArgs.payloadSize = 32;
        macArgs.mac32 = zero32;
        macArgs.nonce32 = zero32;

        TEST(NCVerifyMac(NULL, &secKey, &pubKey, &macArgs),     ARG_ERROR_POS_0)
        TEST(NCVerifyMac(ctx, NULL, &pubKey, &macArgs),        ARG_ERROR_POS_1)
        TEST(NCVerifyMac(ctx, &secKey, NULL, &macArgs),        ARG_ERROR_POS_2)
        TEST(NCVerifyMac(ctx, &secKey, &pubKey, NULL),         ARG_ERROR_POS_3)

        macArgs.payload = NULL;
        TEST(NCVerifyMac(ctx, &secKey, &pubKey, &macArgs), ARG_INVALID_ERROR_POS_3)

        macArgs.payload = zero32;
        macArgs.payloadSize = 0;
        TEST(NCVerifyMac(ctx, &secKey, &pubKey, &macArgs), ARG_RANGE_ERROR_POS_3)
    }

    ENSURE(NCDestroyContext(ctx) == NC_SUCCESS);

#ifdef NOSCRYPTUTIL_H
        NCUtilContextFree(ctx);
#else
        free(ctx);
#endif

    return 0;
}

#endif 

static int TestKnownKeys(void)
{   
    NCPublicKey pubKey;
    span_t secKey1, pubKey1, secKey2, pubKey2;  
    
    secKey1 = FromHexString("98c642360e7163a66cee5d9a842b252345b6f3f3e21bd3b7635d5e6c20c7ea36", sizeof(NCSecretKey));
    pubKey1 = FromHexString("0db15182c4ad3418b4fbab75304be7ade9cfa430a21c1c5320c9298f54ea5406", sizeof(NCPublicKey));

    secKey2 = FromHexString("3032cb8da355f9e72c9a94bbabae80ca99d3a38de1aed094b432a9fe3432e1f2", sizeof(NCSecretKey));
    pubKey2 = FromHexString("421181660af5d39eb95e48a0a66c41ae393ba94ffeca94703ef81afbed724e5a", sizeof(NCPublicKey));
   
    /*Test known keys*/
    TEST(NCValidateSecretKey(TestContext, NCByteCastToSecretKey(secKey1.data)), NC_SUCCESS);

    /* Recover a public key from secret key 1 */
    TEST(NCGetPublicKey(TestContext, NCByteCastToSecretKey(secKey1.data), &pubKey), NC_SUCCESS);

    /* Ensure the public key matches the known public key value */
    TEST(memcmp(pubKey1.data, &pubKey, sizeof(pubKey)), 0);

    /* Repeat with second key */
    TEST(NCValidateSecretKey(TestContext, NCByteCastToSecretKey(secKey2.data)), NC_SUCCESS);
    TEST(NCGetPublicKey(TestContext, NCByteCastToSecretKey(secKey2.data), &pubKey), NC_SUCCESS);
    TEST(memcmp(pubKey2.data, &pubKey, sizeof(pubKey)), 0);    
  
    return 0;
}

#define TEST_ENC_DATA_SIZE 128

static int TestCorrectEncryption()
{
    NCSecretKey secKey1;
    NCPublicKey pubKey1;
    
    NCSecretKey secKey2;
    NCPublicKey pubKey2;
  
    uint8_t hmacKeyOut[NC_HMAC_KEY_SIZE];
    uint8_t nonce[NC_TEST_NIP44_IV_SIZE];  //nonce is set by cipher spec, shoud use NCEncryptionGetIvSize() in production
    uint8_t mac[NC_ENCRYPTION_MAC_SIZE];

    uint8_t plainText[TEST_ENC_DATA_SIZE];
    uint8_t cipherText[TEST_ENC_DATA_SIZE];
    uint8_t decryptedText[TEST_ENC_DATA_SIZE];
  
    NCEncryptionArgs cryptoData;
    NCMacVerifyArgs macVerifyArgs;   

    ENSURE(NCEncryptionGetIvSize(NC_ENC_VERSION_NIP44) == (uint32_t)sizeof(nonce));
    ENSURE(NCEncryptionSetProperty(&cryptoData, NC_ENC_SET_VERSION, NC_ENC_VERSION_NIP44) == NC_SUCCESS);
    ENSURE(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, nonce, sizeof(nonce)) == NC_SUCCESS);
    ENSURE(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP44_MAC_KEY, hmacKeyOut, NC_HMAC_KEY_SIZE) == NC_SUCCESS);

    /* Assign the encryption material */
    ENSURE(NCEncryptionSetData(&cryptoData, plainText, cipherText, TEST_ENC_DATA_SIZE) == NC_SUCCESS);
   
    macVerifyArgs.nonce32 = nonce;    /* nonce is shared */
    macVerifyArgs.mac32 = mac;
    macVerifyArgs.payload = cipherText;
    macVerifyArgs.payloadSize = TEST_ENC_DATA_SIZE;

    /* init a sending and receiving key */
    FillRandomData(&secKey1, sizeof(NCSecretKey));
    FillRandomData(&secKey2, sizeof(NCSecretKey));
    FillRandomData(plainText, sizeof(plainText));
    /* nonce is shared */
    FillRandomData(nonce, sizeof(nonce));

    ENSURE(NCValidateSecretKey(TestContext, &secKey1) == NC_SUCCESS);
    ENSURE(NCValidateSecretKey(TestContext, &secKey2) == NC_SUCCESS);

    ENSURE(NCGetPublicKey(TestContext, &secKey1, &pubKey1) == NC_SUCCESS);
    ENSURE(NCGetPublicKey(TestContext, &secKey2, &pubKey2) == NC_SUCCESS);

    /* Try to encrypt the data from sec1 to pub2 */
    TEST(NCEncrypt(TestContext, &secKey1, &pubKey2, &cryptoData), NC_SUCCESS);

    /*swap cipher and plain text for decryption */
    cryptoData.inputData = cipherText;
    cryptoData.outputData = decryptedText;

    /* Try to decrypt the data from sec1 to pub2 */
    TEST(NCDecrypt(TestContext, &secKey2, &pubKey1, &cryptoData), NC_SUCCESS);

    /* Ensure the decrypted text matches the original */
    TEST(memcmp(plainText, decryptedText, sizeof(plainText)), 0);

    /* Compute message mac on ciphertext */
    TEST(NCComputeMac(TestContext, hmacKeyOut, cipherText, sizeof(cipherText), mac), NC_SUCCESS);

    /* Verify the mac */
    TEST(NCVerifyMac(TestContext, &secKey1, &pubKey2, &macVerifyArgs), NC_SUCCESS);

    return 0;
}

static int RunTests(void)
{
    NCSecretKey secKey;
    NCPublicKey pubKey;

    RUN_TEST(InitKepair(&secKey, &pubKey));

    RUN_TEST(TestEcdsa(&secKey, &pubKey));

    RUN_TEST(TestKnownKeys());

    RUN_TEST(TestCorrectEncryption());

#ifndef NC_INPUT_VALIDATION_OFF

    RUN_TEST(TestPublicApiArgumentValidation());

#endif

    return 0;
}
