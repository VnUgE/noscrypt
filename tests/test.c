/*
* Copyright (c) 2024 Vaughn Nugent
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
* along with NativeHeapApi. If not, see http://www.gnu.org/licenses/.
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <noscrypt.h>
#include <mbedtls/sha256.h>
#include <mbedtls/platform_util.h>

#if defined(_MSC_VER) || defined(WIN32) || defined(_WIN32)
	#define IS_WINDOWS
#endif

#ifdef IS_WINDOWS
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
	#include <wincrypt.h>
#endif

#ifdef IS_WINDOWS
    /*Asserts that an internal test condition is true, otherwise aborts the test process*/
    #define TASSERT(x) if(!(x)) { printf("ERROR! Internal test assumption failed: %s.\n Aborting tests...\n", #x); ExitProcess(1); }
#else
    /*Asserts that an internal test condition is true, otherwise aborts the test process*/
	#define TASSERT(x) if(!(x)) { printf("Internal assumption failed: %s\n", #x); exit(1); }
#endif

/*Prints a string literal to the console*/
#define PRINTL(x) printf(x); printf("\n");
#define ENSURE(x) if(!(x)) { printf("Assumption failed!\n"); return 1; } 
#define TEST(x, expected) printf("\tTesting %s\n", #x); if(((long)x) != ((long)expected)) \
{ printf("FAILED: Expected %ld but got %ld @ callsite %s. Line: %d \n", ((long)expected), ((long)x), #x, __LINE__); return 1; }


#ifdef IS_WINDOWS
    #define ZERO_FILL(x, size) SecureZeroMemory(x, size)
#else
	#define ZERO_FILL(x, size) memset(x, 0, size)
#endif

//Pre-computed constants for argument errors
#define ARG_ERROR_POS_0 E_NULL_PTR
#define ARG_ERROR_POS_1 NCResultWithArgPosition(E_NULL_PTR, 0x01)
#define ARG_ERROR_POS_2 NCResultWithArgPosition(E_NULL_PTR, 0x02)
#define ARG_ERROR_POS_3 NCResultWithArgPosition(E_NULL_PTR, 0x03)
#define ARG_ERROR_POS_4 NCResultWithArgPosition(E_NULL_PTR, 0x04)
#define ARG_ERROR_POS_5 NCResultWithArgPosition(E_NULL_PTR, 0x05)
#define ARG_ERROR_POS_6 NCResultWithArgPosition(E_NULL_PTR, 0x06)

#define ARG_RAMGE_ERROR_POS_0 E_ARGUMENT_OUT_OF_RANGE
#define ARG_RAMGE_ERROR_POS_1 NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, 0x01)
#define ARG_RAMGE_ERROR_POS_2 NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, 0x02)
#define ARG_RAMGE_ERROR_POS_3 NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, 0x03)
#define ARG_RAMGE_ERROR_POS_4 NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, 0x04)
#define ARG_RAMGE_ERROR_POS_5 NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, 0x05)
#define ARG_RAMGE_ERROR_POS_6 NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, 0x06)

#define ARG_INVALID_ERROR_POS_0 E_INVALID_ARG
#define ARG_INVALID_ERROR_POS_1 NCResultWithArgPosition(E_INVALID_ARG, 0x01)
#define ARG_INVALID_ERROR_POS_2 NCResultWithArgPosition(E_INVALID_ARG, 0x02)
#define ARG_INVALID_ERROR_POS_3 NCResultWithArgPosition(E_INVALID_ARG, 0x03)
#define ARG_INVALID_ERROR_POS_4 NCResultWithArgPosition(E_INVALID_ARG, 0x04)
#define ARG_INVALID_ERROR_POS_5 NCResultWithArgPosition(E_INVALID_ARG, 0x05)
#define ARG_INVALID_ERROR_POS_6 NCResultWithArgPosition(E_INVALID_ARG, 0x06)



static void FillRandomData(void* pbBuffer, size_t length);
static int TestEcdsa(NCContext* context, NCSecretKey* secKey, NCPublicKey* pubKey);
static int InitKepair(NCContext* context, NCSecretKey* secKey, NCPublicKey* pubKey);

#ifndef NC_INPUT_VALIDATION_OFF
static int TestPublicApiArgumentValidation(void);
#endif

static const uint8_t zero32[32] = { 0 };
static const uint8_t zero64[64] = { 0 };

int main(void)
{
    NCContext ctx;
    uint8_t ctxRandom[32];
    NCSecretKey secKey;
    NCPublicKey pubKey;

    PRINTL("Begining basic noscrypt tests\n")

    FillRandomData(ctxRandom, 32);

    //Context struct size should aways match the size of the struct returned by NCGetContextStructSize
    TEST(NCGetContextStructSize(), sizeof(NCContext))
    TEST(NCInitContext(&ctx, ctxRandom), NC_SUCCESS)

    if (InitKepair(&ctx, &secKey, &pubKey) != 0)
	{
		return 1;
	}
	
    if (TestEcdsa(&ctx, &secKey, &pubKey) != 0)
    {
        return 1;
    }

#ifndef NC_INPUT_VALIDATION_OFF
    if(TestPublicApiArgumentValidation() != 0)
	{
		return 1;
	}
#endif

    PRINTL("ECDSA tests passed\n")

    TEST(NCDestroyContext(&ctx), NC_SUCCESS)

	return 0;
}

static void _sha256(const uint8_t* data, size_t length, uint8_t digest[32])
{
	mbedtls_sha256_context sha256;
	mbedtls_sha256_init(&sha256);
    TASSERT(0 == mbedtls_sha256_starts(&sha256, 0))
    TASSERT(0 == mbedtls_sha256_update(&sha256, data, length))
    TASSERT(0 == mbedtls_sha256_finish(&sha256, digest))
    mbedtls_sha256_free(&sha256);
}

static const char* message = "Test message to sign";

static int InitKepair(NCContext* context, NCSecretKey* secKey, NCPublicKey* pubKey)
{
    PRINTL("TEST: Keypair\n")

    //Get random private key
    FillRandomData(secKey, sizeof(NCSecretKey));

    //Ensure not empty
    ENSURE(memcmp(zero32, secKey, 32) != 0);

    //Ensure the key is valid, result should be 1 on success
    TEST(NCValidateSecretKey(context, secKey), 1);

    //Generate a public key from the secret key
    TEST(NCGetPublicKey(context, secKey, pubKey), NC_SUCCESS);

    PRINTL("\nPASSED: Keypair tests completed\n")

    return 0;
}

static int TestEcdsa(NCContext* context, NCSecretKey* secKey, NCPublicKey* pubKey)
{   
    uint8_t digestToSign[32];
    uint8_t sigEntropy[32];
    uint8_t invalidSig[64];

    PRINTL("TEST: Ecdsa\n")

    //Init a new secret key with random data
    FillRandomData(invalidSig, sizeof(invalidSig));
    FillRandomData(sigEntropy, sizeof(sigEntropy));

    //compute sha256 of the test string
    _sha256((uint8_t*)message, strlen(message), digestToSign);

    //Sign and verify sig64
    {
		uint8_t sig[64];
        TEST(NCSignDigest(context, secKey, sigEntropy, digestToSign, sig), NC_SUCCESS);
        TEST(NCVerifyDigest(context, pubKey, digestToSign, sig), NC_SUCCESS);
    }
    
    //Sign and verify raw data
    {
        uint8_t sig[64];
        TEST(NCSignData(context, secKey, sigEntropy, (uint8_t*)message, strlen(message), sig), NC_SUCCESS);
        TEST(NCVerifyData(context, pubKey, (uint8_t*)message, strlen(message), sig), NC_SUCCESS);
    }

    //ensure the signature is the same for signing data and sig64
	{
		uint8_t sig1[64];
		uint8_t sig2[64];

        //Ensure operations succeed but dont print them as test cases
        ENSURE(NCSignData(context, secKey, sigEntropy, (uint8_t*)message, strlen(message), sig1) == NC_SUCCESS);
        ENSURE(NCSignDigest(context, secKey, sigEntropy, digestToSign, sig2) == NC_SUCCESS);
		
        //Perform test
        TEST(memcmp(sig1, sig2, 64), 0);
	}

    //Try signing data then veriyfing the sig64
    {
        uint8_t sig[64];
		
        ENSURE(NCSignData(context, secKey, sigEntropy, (uint8_t*)message, strlen(message), sig) == NC_SUCCESS);
        TEST(NCVerifyDigest(context, pubKey, digestToSign, sig), NC_SUCCESS);

        //Now invert test, zero signature to ensure its overwritten
        ZERO_FILL(sig, sizeof(sig));

        ENSURE(NCSignDigest(context, secKey, sigEntropy, digestToSign, sig) == NC_SUCCESS);
        TEST(NCVerifyData(context, pubKey, (uint8_t*)message, strlen(message), sig), NC_SUCCESS);
	}

    //test verification of invalid signature
    {
        TEST(NCVerifyDigest(context, pubKey, digestToSign, invalidSig), E_INVALID_ARG);
    }

    PRINTL("\nPASSED: Ecdsa tests completed\n")
	return 0;
}

#ifndef NC_INPUT_VALIDATION_OFF

static int TestPublicApiArgumentValidation(void)
{
    NCContext ctx;
    uint8_t ctxRandom[32];
    uint8_t sig64[64];
    NCSecretKey secKey;
    NCPublicKey pubKey;
    NCCryptoData cryptoData;

    PRINTL("TEST: Public API argument validation tests\n")

    FillRandomData(ctxRandom, 32);

    //Test null context
    TEST(NCInitContext(NULL, ctxRandom), ARG_ERROR_POS_0)
    TEST(NCInitContext(&ctx, NULL), ARG_ERROR_POS_1)

    //Test null context
    TEST(NCDestroyContext(NULL), ARG_ERROR_POS_0)

    //reinit
    TEST(NCReInitContext(NULL, ctxRandom), ARG_ERROR_POS_0)
    TEST(NCReInitContext(&ctx, NULL), ARG_ERROR_POS_1)

    //Test null secret key
    TEST(NCGetPublicKey(&ctx, NULL, &pubKey), ARG_ERROR_POS_1)
    TEST(NCGetPublicKey(&ctx, &secKey, NULL), ARG_ERROR_POS_2)

    //Test null secret key
    TEST(NCValidateSecretKey(NULL, &secKey), ARG_ERROR_POS_0)
    TEST(NCValidateSecretKey(&ctx, NULL), ARG_ERROR_POS_1)

    //Verify sig64 args test
    TEST(NCVerifyDigest(NULL, &pubKey, zero32, sig64), ARG_ERROR_POS_0)
    TEST(NCVerifyDigest(&ctx, NULL, zero32, sig64), ARG_ERROR_POS_1)
    TEST(NCVerifyDigest(&ctx, &pubKey, NULL, sig64), ARG_ERROR_POS_2)
    TEST(NCVerifyDigest(&ctx, &pubKey, zero32, NULL), ARG_ERROR_POS_3)

    //Test verify data args
    TEST(NCVerifyData(NULL, &pubKey, zero32, 32, sig64), ARG_ERROR_POS_0)
    TEST(NCVerifyData(&ctx, NULL, zero32, 32, sig64), ARG_ERROR_POS_1)
    TEST(NCVerifyData(&ctx, &pubKey, NULL, 32, sig64), ARG_ERROR_POS_2)
    TEST(NCVerifyData(&ctx, &pubKey, zero32, 0, sig64), ARG_RAMGE_ERROR_POS_3)
    TEST(NCVerifyData(&ctx, &pubKey, zero32, 32, NULL), ARG_ERROR_POS_4)

    //Test null sign data args
    TEST(NCSignData(NULL, &secKey, zero32, zero32, 32, sig64), ARG_ERROR_POS_0)
    TEST(NCSignData(&ctx, NULL, zero32, zero32, 32, sig64), ARG_ERROR_POS_1)
    TEST(NCSignData(&ctx, &secKey, NULL, zero32, 32, sig64), ARG_ERROR_POS_2)
    TEST(NCSignData(&ctx, &secKey, zero32, NULL, 32, sig64), ARG_ERROR_POS_3)
    TEST(NCSignData(&ctx, &secKey, zero32, zero32, 0, sig64), ARG_RAMGE_ERROR_POS_4)
    TEST(NCSignData(&ctx, &secKey, zero32, zero32, 32, NULL), ARG_ERROR_POS_5)
   
    //Test null sign digest args
    TEST(NCSignDigest(NULL, &secKey, zero32, zero32, sig64), ARG_ERROR_POS_0)
    TEST(NCSignDigest(&ctx, NULL, zero32, zero32, sig64), ARG_ERROR_POS_1)
    TEST(NCSignDigest(&ctx, &secKey, NULL, zero32, sig64), ARG_ERROR_POS_2)
	TEST(NCSignDigest(&ctx, &secKey, zero32, NULL, sig64), ARG_ERROR_POS_3)
    TEST(NCSignDigest(&ctx, &secKey, zero32, zero32, NULL), ARG_ERROR_POS_4)


    //Encrypt
    cryptoData.dataSize = 32;
    cryptoData.inputData = zero32;
    cryptoData.outputData = sig64;
    FillRandomData(&cryptoData.nonce, 32);

    TEST(NCEncrypt(NULL, &secKey, &pubKey, &cryptoData), ARG_ERROR_POS_0)
    TEST(NCEncrypt(&ctx, NULL, &pubKey, &cryptoData), ARG_ERROR_POS_1)
	TEST(NCEncrypt(&ctx, &secKey, NULL, &cryptoData), ARG_ERROR_POS_2)
    TEST(NCEncrypt(&ctx, &secKey, &pubKey, NULL), ARG_ERROR_POS_3)

    //Test invalid data size
    cryptoData.dataSize = 0;
    TEST(NCEncrypt(&ctx, &secKey, &pubKey, &cryptoData), ARG_RAMGE_ERROR_POS_3)
    
    //Test null input data
    cryptoData.dataSize = 32;
    cryptoData.inputData = NULL;
	TEST(NCEncrypt(&ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)

    //Test null output data
	cryptoData.inputData = zero32;
    cryptoData.outputData = NULL;
	TEST(NCEncrypt(&ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)

    //Decrypt
    cryptoData.dataSize = 32;
    cryptoData.inputData = zero32;
    cryptoData.outputData = sig64;

    TEST(NCDecrypt(NULL, &secKey, &pubKey, &cryptoData), ARG_ERROR_POS_0)
    TEST(NCDecrypt(&ctx, NULL, &pubKey, &cryptoData), ARG_ERROR_POS_1)
	TEST(NCDecrypt(&ctx, &secKey, NULL, &cryptoData), ARG_ERROR_POS_2)
    TEST(NCDecrypt(&ctx, &secKey, &pubKey, NULL), ARG_ERROR_POS_3)

    //Test invalid data size
	cryptoData.dataSize = 0;
    TEST(NCDecrypt(&ctx, &secKey, &pubKey, &cryptoData), ARG_RAMGE_ERROR_POS_3)

    //Test null input data
	cryptoData.dataSize = 32;
    cryptoData.inputData = NULL;
	TEST(NCDecrypt(&ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)

    //Test null output data
    cryptoData.inputData = zero32;
    cryptoData.outputData = NULL;
	TEST(NCDecrypt(&ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)

    PRINTL("\nPASSED: Public API argument validation tests completed\n")

    return 0;
}

#endif

static void FillRandomData(void* pbBuffer, size_t length)
{

#ifdef IS_WINDOWS

    HCRYPTPROV hCryptProv;

    TASSERT(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0));
    TASSERT(CryptGenRandom(hCryptProv, (DWORD)length, pbBuffer))
    TASSERT(CryptReleaseContext(hCryptProv, 0));
#else
    FILE* f = fopen("/dev/urandom", "rb");
	TASSERT(f != NULL);
	TASSERT(fread(pbBuffer, 1, length, f) == length);
	fclose(f);
#endif
}