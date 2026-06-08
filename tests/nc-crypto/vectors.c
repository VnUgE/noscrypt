/*
* Copyright (c) 2026 Vaughn Nugent
*
* Package: noscrypt
* File: vectors.c
*
* Known-answer vector tests for the nc-crypto stream API.
*
* Test vectors from:
*   SHA-256:  NIST FIPS 180-2 (change notice 1)
*             https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
*
*   HMAC-SHA-256: RFC 4231
*                 https://www.ietf.org/rfc/rfc4231.txt
*
*   HKDF-SHA-256: RFC 5869
*                  https://www.ietf.org/rfc/rfc5869.txt
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public License
* as published by the Free Software Foundation; either version 2.1
* of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with noscrypt. If not, see http://www.gnu.org/licenses/.
*/

#include <test.h>
#include <span.h>
#include <hex.h>

#define _NCC_API NC_EXPORT
#include <nc-crypto.h>

int VectorTests(void);

#ifndef VECTOR_TESTS
	#define VECTOR_TESTS 1

	static int hashStreamFull(uint32_t flags, cspan_t key, cspan_t source, span_t output)
	{
		ncc_digest_t stream;

		ENSURE(ncCryptoDigestCreate(&stream, flags));
		ENSURE(ncCryptoDigestInit(&stream, key));
		ENSURE(ncCryptoDigestUpdate(&stream, source));
		ENSURE(ncCryptoDigestFinish(&stream, output));
		ncCryptoDigestClose(&stream);

		return 0;
	}

	/*
	* SHA-256: empty string
	* Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	*/
	static int TestSha256Empty(void)
	{		
		uint8_t actual[SHA256_DIGEST_SIZE];
		cspan_t emptyInput;
		span_t outSpan;

		span_t expected = FromHexString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", SHA256_DIGEST_SIZE);

		spanInitC(&emptyInput, NULL, 0);
		spanInit(&outSpan, actual, sizeof(actual));

		EXPECT_EQ(hashStreamFull(NC_CRYPTO_DIGEST_TYPE_SHA256, emptyInput, emptyInput, outSpan), 0);

		EXPECT_EQ(memcmp(actual, spanGetOffset(expected, 0), SHA256_DIGEST_SIZE), 0u);

		return 0;
	}

	/*
	* SHA-256: "abc" (0x616263)
	* Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	*/
	static int TestSha256Abc(void)
	{
		uint8_t actual[SHA256_DIGEST_SIZE];
		uint8_t input[] = { 0x61, 0x62, 0x63 };
		cspan_t data;
		cspan_t emptyKey;
		span_t outSpan;
		
		span_t expected = FromHexString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", SHA256_DIGEST_SIZE);

		spanInitC(&data, input, sizeof(input));
		spanInitC(&emptyKey, NULL, 0);
		spanInit(&outSpan, actual, sizeof(actual));	

		EXPECT_EQ(hashStreamFull(NC_CRYPTO_DIGEST_TYPE_SHA256, emptyKey, data, outSpan), 0);	

		EXPECT_EQ(memcmp(actual, spanGetOffset(expected, 0), SHA256_DIGEST_SIZE), 0u);

		return 0;
	}

	/*
	* HMAC-SHA-256: RFC 4231 Test Case 1
	* Key = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
	* Data = "Hi There"
	* Expected: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
	*/
	static int TestHmacSha256Tc1(void)
	{		
		uint8_t actual[SHA256_DIGEST_SIZE];
		span_t outSpan;
		uint32_t flags;

		span_t key = FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 20);
		span_t data = FromHexString("4869205468657265", 8);
		span_t expected = FromHexString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", SHA256_DIGEST_SIZE);

		spanInit(&outSpan, actual, sizeof(actual));

		flags = NC_CRYPTO_DIGEST_TYPE_SHA256 | NC_CRYPTO_DIGEST_FLAGS_HMAC;

		EXPECT_EQ(hashStreamFull(flags, spanToC(key), spanToC(data), outSpan), 0);

		EXPECT_EQ(memcmp(actual, spanGetOffset(expected, 0), SHA256_DIGEST_SIZE), 0u);

		return 0;
	}

	/*
	* HMAC-SHA-256: RFC 4231 Test Case 2
	* Key = "Jefe" (4a656665)
	* Data = "what do ya want for nothing?"
	* Expected: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
	*/
	static int TestHmacSha256Tc2(void)
	{		
		span_t outSpan;
		uint8_t actual[SHA256_DIGEST_SIZE];

		uint32_t flags = NC_CRYPTO_DIGEST_TYPE_SHA256 | NC_CRYPTO_DIGEST_FLAGS_HMAC;

		span_t key = FromHexString("4a656665", 4);
		span_t data = FromHexString("7768617420646f2079612077616e7420666f72206e6f7468696e673f", 28);
		span_t expected = FromHexString("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", SHA256_DIGEST_SIZE);

		spanInit(&outSpan, actual, sizeof(actual));

		EXPECT_EQ(hashStreamFull(flags, spanToC(key), spanToC(data), outSpan), 0);

		EXPECT_EQ(memcmp(actual, spanGetOffset(expected, 0), SHA256_DIGEST_SIZE), 0u);

		return 0;
	}

	/*
	* HMAC-SHA-256: RFC 4231 Test Case 6
	* Key = 0xaa repeated 131 bytes (larger than SHA-256 block size of 64)
	* Data = "Test Using Larger Than Block-Size Key - Hash Key First"
	* Expected: 60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54
	*
	* Tests that HMAC correctly hashes oversized keys before
	* deriving the inner/outer pad keys
	*/
	static int TestHmacSha256Tc6(void)
	{		
		/* 0x19 repeated 131 times (0x19 = 25 decimal) */
		uint8_t keyBuf[131];
		uint8_t actual[SHA256_DIGEST_SIZE];
		cspan_t key;
		span_t outSpan;

		uint32_t flags = NC_CRYPTO_DIGEST_TYPE_SHA256 | NC_CRYPTO_DIGEST_FLAGS_HMAC;	
		
		span_t data = FromHexString("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", 54);
		span_t expected = FromHexString("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", SHA256_DIGEST_SIZE);

		/*
		* Rebuild key from the raw buffer since we need 131 bytes
		* of 0xaa, not a 1-byte hex decode
		*/
		memset(keyBuf, 0xaa, sizeof(keyBuf));
		spanInitC(&key, keyBuf, sizeof(keyBuf));
		spanInit(&outSpan, actual, sizeof(actual));

		EXPECT_EQ(hashStreamFull(flags, key, spanToC(data), outSpan), 0);

		EXPECT_EQ(memcmp(actual, spanGetOffset(expected, 0), SHA256_DIGEST_SIZE), 0u);

		return 0;
	}

	/*
	* HKDF-SHA-256 Expand: RFC 5869 Test Case 1
	* PRK  = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
	* Info = f0f1f2f3f4f5f6f7f8f9
	* L    = 42
	* OKM  = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
	*/
	static int TestHkdfExpandTc1(void)
	{
		uint8_t actual[42];
		span_t okm;

		span_t prk = FromHexString("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", SHA256_DIGEST_SIZE);
		span_t info = FromHexString("f0f1f2f3f4f5f6f7f8f9", 10);
		span_t expected = FromHexString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", 42);

		spanInit(&okm, actual, sizeof(actual));

		EXPECT_EQ(ncCryptoSha256HkdfExpand(spanToC(prk), spanToC(info), okm), CSTATUS_OK);
		EXPECT_EQ(memcmp(actual, spanGetOffset(expected, 0), sizeof(actual)), 0u);

		return 0;
	}

	/*
	* HKDF-SHA-256 Expand: RFC 5869 Test Case 3
	* Zero-length info
	* PRK  = 19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04
	* Info = (empty)
	* L    = 42
	* OKM  = 8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8
	*/
	static int TestHkdfExpandTc3(void)
	{
		uint8_t actual[42];
		span_t okm;
		cspan_t info;

		span_t prk = FromHexString("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", SHA256_DIGEST_SIZE);
		span_t expected = FromHexString("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", 42);

		spanInitC(&info, NULL, 0);
		spanInit(&okm, actual, sizeof(actual));

		EXPECT_TRUE(ncCryptoSha256HkdfExpand(spanToC(prk), info, okm));
		EXPECT_EQ(memcmp(actual, spanGetOffset(expected, 0), sizeof(actual)), 0u);

		return 0;
	}

	static cstatus_t _updatePart(ncc_digest_t* stream, uint8_t value)
	{
		cspan_t part;
		spanInitC(&part, &value, 1);
		return ncCryptoDigestUpdate(stream, part);
	}

	/*
	* Multi-Update correctness: feeding "abc" as one call vs
	* three calls must produce the same SHA-256 hash
	*/
	static int TestMultiUpdateCorrectness(void)
	{
		ncc_digest_t stream;
		uint8_t outSingle[SHA256_DIGEST_SIZE];
		uint8_t outChunked[SHA256_DIGEST_SIZE];
		cspan_t emptyKey;
		uint8_t abc[] = { 0x61, 0x62, 0x63 };

		spanInitC(&emptyKey, NULL, 0);		

		/* Single Update */
		{			
			cspan_t fullInput;
			span_t outSingleSpan;
			
			spanInitC(&fullInput, abc, sizeof(abc));
			spanInit(&outSingleSpan, outSingle, sizeof(outSingle));

			EXPECT_EQ(hashStreamFull(NC_CRYPTO_DIGEST_TYPE_SHA256, emptyKey, fullInput, outSingleSpan), 0);
		}

		/* Chunked Update */
		{
			span_t outChunkedSpan;

			spanInit(&outChunkedSpan, outChunked, sizeof(outChunked));

			EXPECT_TRUE(ncCryptoDigestCreate(&stream, NC_CRYPTO_DIGEST_TYPE_SHA256));
			EXPECT_TRUE(ncCryptoDigestInit(&stream, emptyKey));

			EXPECT_TRUE(_updatePart(&stream, abc[0]));
			EXPECT_TRUE(_updatePart(&stream, abc[1]));
			EXPECT_TRUE(_updatePart(&stream, abc[2]));

			EXPECT_TRUE(ncCryptoDigestFinish(&stream, outChunkedSpan));
			ncCryptoDigestClose(&stream);
		}

		EXPECT_EQ(memcmp(outSingle, outChunked, SHA256_DIGEST_SIZE), 0u);

		return 0;
	}

	/*
	* HKDF-SHA-256 Extract: RFC 5869 Test Case 1
	* Salt  = 000102030405060708090a0b0c
	* IKM   = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
	* PRK   = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
	*/
	static int TestHkdfExtractTc1(void)
	{
		uint8_t actual[SHA256_DIGEST_SIZE];

		span_t salt = FromHexString("000102030405060708090a0b0c", 13);
		span_t ikm = FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 22);
		span_t expected = FromHexString("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", SHA256_DIGEST_SIZE);
	

		EXPECT_EQ(ncCryptoSha256HkdfExtract(spanToC(salt), spanToC(ikm), actual), CSTATUS_OK);

		EXPECT_EQ(memcmp(actual, spanGetOffset(expected, 0), SHA256_DIGEST_SIZE), 0u);

		return 0;
	}

	/*
	* HKDF-SHA-256 Extract: RFC 5869 Test Case 3
	* Salt  = (empty)
	* IKM   = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
	* PRK   = 19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04
	*/
	static int TestHkdfExtractTc3(void)
	{
		cspan_t salt;
		uint8_t actual[SHA256_DIGEST_SIZE];
		span_t ikm = FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 22);
		span_t expected = FromHexString("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", SHA256_DIGEST_SIZE);

		spanInitC(&salt, NULL, 0);

		EXPECT_EQ(ncCryptoSha256HkdfExtract(salt, spanToC(ikm), actual), CSTATUS_OK);

		EXPECT_EQ(memcmp(actual, spanGetOffset(expected, 0), SHA256_DIGEST_SIZE), 0u);

		return 0;
	}

	int VectorTests(void)
	{
		RUN_TEST(TestSha256Empty());
		RUN_TEST(TestSha256Abc());
		RUN_TEST(TestHmacSha256Tc1());
		RUN_TEST(TestHmacSha256Tc2());
		RUN_TEST(TestHmacSha256Tc6());

		RUN_TEST(TestHkdfExtractTc1());
		RUN_TEST(TestHkdfExtractTc3());
		RUN_TEST(TestHkdfExpandTc1());
		RUN_TEST(TestHkdfExpandTc3());		

		RUN_TEST(TestMultiUpdateCorrectness());

		return 0;
	}
#endif
