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

#include "../src/noscrypt.h"
#include "../include/mbedtls/sha256.h"

#if defined(_MSC_VER) || defined(WIN32) || defined(_WIN32)
	#define IS_WINDOWS
#endif

#ifdef IS_WINDOWS
	
	#include <windows.h>
	#include <wincrypt.h>

    //Prints a string literal to the console
	#define PRINTL(x) printf(x); printf("\r\n");
    #define TEST(x) printf("Testing %s\n", #x); if(!(x)) { printf("Test failed!\n"); return 1; } else { printf("Test passed\n\n"); }
    #define TASSERT(x) if(!(x)) { printf("ERROR! Internal test assumption failed: %s.\n Aborting tests...\n", #x); ExitProcess(1); }
#else
	#include <stdlib.h>

    //Prints a string literal to the console
	#define PRINTL(x) printf(x); printf("\n");
	#define TEST(x) printf("Testing %s\n", #x); if(!(x)) { printf("Test failed!\n"); return 1; } else { printf("Test passed\n\n"); }
	#define TASSERT(x) if(!(x)) { printf("Internal assumption failed: %s\n", #x); exit(1); }
#endif

static void FillRandomData(uint8_t* pbBuffer, size_t length);
static int TestEcdsa(NCContext* context);

int main(char* argv[], int argc)
{
    NCContext ctx;
    uint8_t ctxRandom[32];

    PRINTL("Begining basic noscrypt tests\n")

    FillRandomData(ctxRandom, 32);

    //Context struct size should aways match the size of the struct returned by NCGetContextStructSize
    TEST(NCGetContextStructSize() == sizeof(NCContext))  

    TEST(NCInitContext(&ctx, ctxRandom) == NC_SUCCESS)
	
    if (TestEcdsa(&ctx) != 0)
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

static int TestEcdsa(NCContext* context) 
{
    uint8_t digestToSign[32];
    uint8_t secretKey[NC_SEC_KEY_SIZE];
    uint8_t publicKey[NC_PUBKEY_SIZE];
    uint8_t sigEntropy[32];
    uint8_t invalidSig[64];
    NCSecretKey* secKey;
    NCPublicKey* pubKey;

    PRINTL("Begining basic Nostr ECDSA tests")

    //Convert to internal key structs
    secKey = NCToSecKey(secretKey);
    pubKey = NCToPubKey(publicKey);

    TEST((&secKey->key) == &secretKey);

    //Init a new secret key with random data
    FillRandomData(secretKey, sizeof(secretKey));
    FillRandomData(invalidSig, sizeof(invalidSig));
    FillRandomData(sigEntropy, sizeof(sigEntropy));

    //Verify that the secret key is valid for the curve
    TEST(NCValidateSecretKey(context, secKey) == NC_SUCCESS);

    //Generate a public key from the secret key
    TEST(NCGetPublicKey(context, secKey, pubKey) == NC_SUCCESS);

    //Sign and verify digest
    {
		uint8_t sig[64];
		
        //compute sha256 of the test string
        _sha256((uint8_t*)message, strlen(message), digestToSign);

        TEST(NCSignDigest(context, secKey, sigEntropy, digestToSign, sig) == NC_SUCCESS);
		TEST(NCVerifyDigest(context, pubKey, digestToSign, sig) == NC_SUCCESS);
    }
    
    //Sign and verify raw data
    {
        uint8_t sig[64];
		TEST(NCSignData(context, secKey, sigEntropy, (uint8_t*)message, strlen(message), sig) == NC_SUCCESS);
        TEST(NCVerifyData(context, pubKey, (uint8_t*)message, strlen(message), sig) == NC_SUCCESS);
    }

    //test verification of invalid signature
    {
        TEST(NCVerifyDigest(context, pubKey, digestToSign, invalidSig) == E_INVALID_ARG);
    }

	return 0;
}

static const char* encMessage = "Test message to encrypt";

static int TestEcdh(NCContext* ctx)
{
    PRINTL("Begining basic Nostr Encryption tests")
}

static void FillRandomData(uint8_t* pbBuffer, size_t length)
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