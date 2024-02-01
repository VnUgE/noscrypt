/*
* Copyright (c) 2024 Vaughn Nugent
*
* Library: noscrypt
* Package: noscrypt
* File: test.c
*
* noscrypt is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published
* by the Free Software Foundation, either version 2 of the License,
* or (at your option) any later version.
*
* noscrypt is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with noscrypt. If not, see http://www.gnu.org/licenses/.
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

    //Prints a string literal to the console
	#define PRINTL(x) printf(x); printf("\r\n");
    #define TEST(x) printf("\tTesting %s\n", #x); if(!(x)) { printf("TEST FAILED!\n"); return 1; } else { printf("\tTest passed\n\n"); }
    #define TASSERT(x) if(!(x)) { printf("ERROR! Internal test assumption failed: %s.\n Aborting tests...\n", #x); ExitProcess(1); }
    #define ENSURE(x) if(!(x)) { printf("Assumption failed! %s\n", #x); return 1; } 
#else

    //Prints a string literal to the console
	#define PRINTL(x) printf(x); printf("\n");
	#define TEST(x) printf("\tTesting %s\n", #x); if(!(x)) { printf("TEST FAILED!\n"); return 1; } else { printf("\tTest passed\n\n"); }
	#define TASSERT(x) if(!(x)) { printf("Internal assumption failed: %s\n", #x); exit(1); }
    #define ENSURE(x) if(!(x)) { printf("Assumption failed!\n"); return 1; } 
#endif

#ifdef IS_WINDOWS
    #define ZERO_FILL(x, size) SecureZeroMemory(x, size)
#else
	#define ZERO_FILL(x, size) memset(x, 0, size)
#endif

static void FillRandomData(void* pbBuffer, size_t length);
static int TestEcdsa(NCContext* context, NCSecretKey* secKey, NCPublicKey* pubKey);
static int InitKepair(NCContext* context, NCSecretKey* secKey, NCPublicKey* pubKey);

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
    TEST(NCGetContextStructSize() == sizeof(NCContext))  

    TEST(NCInitContext(&ctx, ctxRandom) == NC_SUCCESS)

    if (InitKepair(&ctx, &secKey, &pubKey) != 0)
	{
		return 1;
	}
	
    if (TestEcdsa(&ctx, &secKey, &pubKey) != 0)
    {
        return 1;
    }

    PRINTL("ECDSA tests passed\n")

    TEST(NCDestroyContext(&ctx) == NC_SUCCESS)

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
    PRINTL("TEST: Keypair")

    //Get random private key
    FillRandomData(secKey, sizeof(NCSecretKey));

    //Ensure not empty
    ENSURE(memcmp(zero32, secKey, 32) != 0);

    //Ensure the key is valid
    TEST(NCValidateSecretKey(context, secKey) == NC_SUCCESS);

    //Generate a public key from the secret key
    TEST(NCGetPublicKey(context, secKey, pubKey) == NC_SUCCESS);

    return 0;
}

static int TestEcdsa(NCContext* context, NCSecretKey* secKey, NCPublicKey* pubKey)
{   
    uint8_t digestToSign[32];
    uint8_t sigEntropy[32];
    uint8_t invalidSig[64];

    PRINTL("TEST: Ecdsa")

    //Init a new secret key with random data
    FillRandomData(invalidSig, sizeof(invalidSig));
    FillRandomData(sigEntropy, sizeof(sigEntropy));

    //compute sha256 of the test string
    _sha256((uint8_t*)message, strlen(message), digestToSign);

    //Sign and verify digest
    {
		uint8_t sig[64];
        TEST(NCSignDigest(context, secKey, sigEntropy, digestToSign, sig) == NC_SUCCESS);
		TEST(NCVerifyDigest(context, pubKey, digestToSign, sig) == NC_SUCCESS);
    }
    
    //Sign and verify raw data
    {
        uint8_t sig[64];
		TEST(NCSignData(context, secKey, sigEntropy, (uint8_t*)message, strlen(message), sig) == NC_SUCCESS);
        TEST(NCVerifyData(context, pubKey, (uint8_t*)message, strlen(message), sig) == NC_SUCCESS);
    }

    //ensure the signature is the same for signing data and digest
	{
		uint8_t sig1[64];
		uint8_t sig2[64];

        //Ensure operations succeed but dont print them as test cases
        ENSURE(NCSignData(context, secKey, sigEntropy, (uint8_t*)message, strlen(message), sig1) == NC_SUCCESS);
        ENSURE(NCSignDigest(context, secKey, sigEntropy, digestToSign, sig2) == NC_SUCCESS);
		
        //Perform test
        TEST(memcmp(sig1, sig2, 64) == 0);
	}

    //Try signing data then veriyfing the digest
    {
        uint8_t sig[64];
		
        ENSURE(NCSignData(context, secKey, sigEntropy, (uint8_t*)message, strlen(message), sig) == NC_SUCCESS);
        TEST(NCVerifyDigest(context, pubKey, digestToSign, sig) == NC_SUCCESS);

        //Now invert test, zero signature to ensure its overwritten
        ZERO_FILL(sig, sizeof(sig));

        ENSURE(NCSignDigest(context, secKey, sigEntropy, digestToSign, sig) == NC_SUCCESS);
        TEST(NCVerifyData(context, pubKey, (uint8_t*)message, strlen(message), sig) == NC_SUCCESS);
	}

    //test verification of invalid signature
    {

        TEST(NCVerifyDigest(context, pubKey, digestToSign, invalidSig) == E_INVALID_ARG);
    }

	return 0;
}

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