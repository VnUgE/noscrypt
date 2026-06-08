/*
* Copyright (c) 2026 Vaughn Nugent
*
* Package: noscrypt
* File: stream.c
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

#define _NCC_API NC_EXPORT
#include <nc-crypto.h>


#ifndef STREAM_CONTRACT_TESTS
	#define STREAM_CONTRACT_TESTS 1

	int StreamTests(void);

	// Tests that HMAC mode rejects an empty key and plain digest accepts one
	static int TestDigestInitSuccess(void)
	{
		ncc_digest_t stream;

		// HMAC stream with key should succeed
		{
			uint8_t keyBuf[32];
			cspan_t key;

			spanInitC(&key, keyBuf, sizeof(keyBuf));
			ZERO_FILL(keyBuf, sizeof(keyBuf));

			uint32_t flags = NC_CRYPTO_DIGEST_TYPE_SHA256 | NC_CRYPTO_DIGEST_FLAGS_HMAC;

			EXPECT_TRUE(ncCryptoDigestCreate(&stream, flags));
			EXPECT_EQ(ncCryptoDigestInit(&stream, key), CSTATUS_OK);

			ncCryptoDigestClose(&stream);
		}

		// Plain digest stream with empty key must succeed
		{
			cspan_t emptyKey;
			spanInitC(&emptyKey, NULL, 0);

			uint32_t flags = NC_CRYPTO_DIGEST_TYPE_SHA256;

			EXPECT_TRUE(ncCryptoDigestCreate(&stream, flags));
			EXPECT_EQ(ncCryptoDigestInit(&stream, emptyKey), CSTATUS_OK);

			ncCryptoDigestClose(&stream);
		}

		return 0;
	}

	// Tests that Close is idempotent: zeroed stream and double-close are safe no-ops
	static int TestCloseSafeNoop(void)
	{
		ncc_digest_t stream;

		// Zeroed/uninitialized stream must not crash
		ZERO_FILL(&stream, sizeof(stream));
		ncCryptoDigestClose(&stream);

		// Double close must not crash
		EXPECT_TRUE(ncCryptoDigestCreate(&stream, NC_CRYPTO_DIGEST_TYPE_SHA256));
		ncCryptoDigestClose(&stream);
		ncCryptoDigestClose(&stream);

		return 0;
	}

	// Tests that GetOutputSize returns SHA256_DIGEST_SIZE for both plain and HMAC streams
	static int TestGetOutputSizeSha256(void)
	{
		ncc_digest_t stream;

		// Plain SHA-256 stream reports 32 bytes
		{
			EXPECT_TRUE(ncCryptoDigestCreate(&stream, NC_CRYPTO_DIGEST_TYPE_SHA256));
			EXPECT_EQ(ncCryptoDigestGetOutputSize(&stream), (uint32_t)SHA256_DIGEST_SIZE);

			ncCryptoDigestClose(&stream);
		}

		// HMAC SHA-256 stream also reports 32 bytes
		{
			uint32_t flags = NC_CRYPTO_DIGEST_TYPE_SHA256 | NC_CRYPTO_DIGEST_FLAGS_HMAC;

			EXPECT_TRUE(ncCryptoDigestCreate(&stream, flags));
			EXPECT_EQ(ncCryptoDigestGetOutputSize(&stream), (uint32_t)SHA256_DIGEST_SIZE);

			ncCryptoDigestClose(&stream);
		}

		return 0;
	}

	// Tests that a plain SHA-256 digest stream produces identical output
	// across multiple Init/Update/Finish cycles (reuse via ResetLoop)
	static int TestDigestResetLoop(void)
	{
		ncc_digest_t stream;
		cspan_t emptyKey;
		uint8_t out1[SHA256_DIGEST_SIZE];
		uint8_t out2[SHA256_DIGEST_SIZE];
		cspan_t data;
		uint8_t buf[] = { 0x61, 0x62, 0x63 }; // "abc"
		uint32_t flags = NC_CRYPTO_DIGEST_TYPE_SHA256 | NC_CRYPTO_DIGEST_FLAGS_REUSE;

		spanInitC(&emptyKey, NULL, 0);
		spanInitC(&data, buf, sizeof(buf));

		ZERO_FILL(out1, sizeof(out1));
		ZERO_FILL(out2, sizeof(out2));

		EXPECT_TRUE(ncCryptoDigestCreate(&stream, flags));
		EXPECT_TRUE(ncCryptoDigestInit(&stream, emptyKey));

		// First iteration: hash "abc"
		{
			span_t outSpan;
			spanInit(&outSpan, out1, sizeof(out1));

			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, data));
			EXPECT_TRUE(ncCryptoDigestFinish(&stream, outSpan));
		}

		// Reset and hash "abc" again — must produce identical output
		{
			span_t outSpan;
			spanInit(&outSpan, out2, sizeof(out2));

			EXPECT_TRUE(ncCryptoDigestInit(&stream, emptyKey));
			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, data));
			EXPECT_TRUE(ncCryptoDigestFinish(&stream, outSpan));
		}

		ncCryptoDigestClose(&stream);

		EXPECT_EQ(memcmp(out1, out2, SHA256_DIGEST_SIZE), 0u);

		return 0;
	}

	// Tests that an HMAC-SHA-256 stream produces identical output
	// across multiple Init/Update/Finish cycles (reuse via ResetLoop)
	static int TestHmacResetLoop(void)
	{
		ncc_digest_t stream;
		// RFC 4231 Test Case 1 key: 0x0b repeated 20 times
		uint8_t keyBuf[] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
							 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
							 0x0b, 0x0b, 0x0b, 0x0b };
		cspan_t key;
		uint8_t out1[SHA256_DIGEST_SIZE];
		uint8_t out2[SHA256_DIGEST_SIZE];
		cspan_t data;
		// "Hi There"
		uint8_t buf[] = { 0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65 };

		uint32_t flags = NC_CRYPTO_DIGEST_TYPE_SHA256 
			| NC_CRYPTO_DIGEST_FLAGS_HMAC 
			| NC_CRYPTO_DIGEST_FLAGS_REUSE;

		spanInitC(&key, keyBuf, sizeof(keyBuf));
		spanInitC(&data, buf, sizeof(buf));

		ZERO_FILL(out1, sizeof(out1));
		ZERO_FILL(out2, sizeof(out2));

		EXPECT_TRUE(ncCryptoDigestCreate(&stream, flags));
		EXPECT_TRUE(ncCryptoDigestInit(&stream, key));

		{
			span_t outSpan;
			spanInit(&outSpan, out1, sizeof(out1));

			// First iteration: HMAC(key, "Hi There")
			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, data));
			EXPECT_TRUE(ncCryptoDigestFinish(&stream, outSpan));
		}

		EXPECT_TRUE(ncCryptoDigestInit(&stream, key));

		// Reset and HMAC again — must produce identical output
		{
			span_t outSpan;
			spanInit(&outSpan, out2, sizeof(out2));

			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, data));
			EXPECT_TRUE(ncCryptoDigestFinish(&stream, outSpan));
		}

		ncCryptoDigestClose(&stream);

		EXPECT_EQ(memcmp(out1, out2, SHA256_DIGEST_SIZE), 0u);

		return 0;
	}

	/*
	* Tests that resetting a digest stream with different data
	* produces different output, proving the stream actually resets
	*/
	static int TestResetWithDifferentData(void)
	{
		ncc_digest_t stream;
		cspan_t emptyKey;
		uint8_t out1[SHA256_DIGEST_SIZE];
		uint8_t out2[SHA256_DIGEST_SIZE];

		uint32_t flags = NC_CRYPTO_DIGEST_TYPE_SHA256 | NC_CRYPTO_DIGEST_FLAGS_REUSE;

		spanInitC(&emptyKey, NULL, 0);

		ZERO_FILL(out1, sizeof(out1));
		ZERO_FILL(out2, sizeof(out2));

		EXPECT_TRUE(ncCryptoDigestCreate(&stream, flags));
		EXPECT_TRUE(ncCryptoDigestInit(&stream, emptyKey));

		/* First: SHA-256("abc") */
		{
			cspan_t data;
			span_t outSpan;
			uint8_t buf[] = { 0x61, 0x62, 0x63 };

			spanInitC(&data, buf, sizeof(buf));
			spanInit(&outSpan, out1, sizeof(out1));

			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, data));
			EXPECT_TRUE(ncCryptoDigestFinish(&stream, outSpan));
		}

		EXPECT_TRUE(ncCryptoDigestInit(&stream, emptyKey));

		/* Second: SHA-256("xyz") — must differ from first */
		{
			cspan_t data;
			span_t outSpan;
			uint8_t buf[] = { 0x78, 0x79, 0x7a };

			spanInitC(&data, buf, sizeof(buf));
			spanInit(&outSpan, out2, sizeof(out2));

			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, data));
			EXPECT_TRUE(ncCryptoDigestFinish(&stream, outSpan));
		}

		ncCryptoDigestClose(&stream);

		EXPECT_TRUE(memcmp(out1, out2, SHA256_DIGEST_SIZE) != 0);

		return 0;
	}

	/*
	* Tests that an empty Update is a no-op: feeding empty data
	* between chunks must produce the same hash as without it
	*/
	static int TestEmptyUpdateNoop(void)
	{
		ncc_digest_t stream;
		cspan_t emptyKey;
		uint8_t out1[SHA256_DIGEST_SIZE];
		uint8_t out2[SHA256_DIGEST_SIZE];

		uint32_t flags = NC_CRYPTO_DIGEST_TYPE_SHA256 | NC_CRYPTO_DIGEST_FLAGS_REUSE;

		spanInitC(&emptyKey, NULL, 0);

		ZERO_FILL(out1, sizeof(out1));
		ZERO_FILL(out2, sizeof(out2));

		EXPECT_TRUE(ncCryptoDigestCreate(&stream, flags));
		EXPECT_TRUE(ncCryptoDigestInit(&stream, emptyKey));

		/* SHA-256("ab" + "c") */
		{
			cspan_t chunk1, chunk2;
			span_t outSpan;
			uint8_t b1[] = { 0x61, 0x62 };
			uint8_t b2[] = { 0x63 };

			spanInitC(&chunk1, b1, sizeof(b1));
			spanInitC(&chunk2, b2, sizeof(b2));
			spanInit(&outSpan, out1, sizeof(out1));

			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, chunk1));
			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, chunk2));
			EXPECT_TRUE(ncCryptoDigestFinish(&stream, outSpan));
		}

		EXPECT_TRUE(ncCryptoDigestInit(&stream, emptyKey));

		/* SHA-256("ab" + "" + "c") — empty Update in between */
		{
			cspan_t chunk1, chunk2, empty;
			span_t outSpan;
			uint8_t b1[] = { 0x61, 0x62 };
			uint8_t b2[] = { 0x63 };

			spanInitC(&chunk1, b1, sizeof(b1));
			spanInitC(&chunk2, b2, sizeof(b2));
			spanInitC(&empty, NULL, 0);
			spanInit(&outSpan, out2, sizeof(out2));

			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, chunk1));
			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, empty));
			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, chunk2));
			EXPECT_TRUE(ncCryptoDigestFinish(&stream, outSpan));
		}

		ncCryptoDigestClose(&stream);

		EXPECT_EQ(memcmp(out1, out2, SHA256_DIGEST_SIZE), 0u);

		return 0;
	}

	/*
	* Tests that resetting a digest stream with different input
	* produces different output, proving the stream state is
	* actually cleared between cycles
	*/
	static int TestDigestResetDifferentData(void)
	{
		ncc_digest_t stream;
		cspan_t emptyKey;
		uint8_t out1[SHA256_DIGEST_SIZE];
		uint8_t out2[SHA256_DIGEST_SIZE];

		uint32_t flags = NC_CRYPTO_DIGEST_TYPE_SHA256 | NC_CRYPTO_DIGEST_FLAGS_REUSE;

		spanInitC(&emptyKey, NULL, 0);

		EXPECT_TRUE(ncCryptoDigestCreate(&stream, flags));
		EXPECT_TRUE(ncCryptoDigestInit(&stream, emptyKey));

		/* First: SHA-256("abc") */
		{
			cspan_t data;
			span_t outSpan;
			uint8_t buf[] = { 0x61, 0x62, 0x63 };

			spanInitC(&data, buf, sizeof(buf));
			spanInit(&outSpan, out1, sizeof(out1));

			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, data));
			EXPECT_TRUE(ncCryptoDigestFinish(&stream, outSpan));
		}

		EXPECT_TRUE(ncCryptoDigestInit(&stream, emptyKey));

		/* Second: SHA-256("xyz") — must differ from first */
		{
			cspan_t data;
			span_t outSpan;
			uint8_t buf[] = { 0x78, 0x79, 0x7a };

			spanInitC(&data, buf, sizeof(buf));
			spanInit(&outSpan, out2, sizeof(out2));

			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, data));
			EXPECT_TRUE(ncCryptoDigestFinish(&stream, outSpan));
		}

		ncCryptoDigestClose(&stream);

		EXPECT_TRUE(memcmp(out1, out2, SHA256_DIGEST_SIZE) != 0);

		return 0;
	}

	/*
	* Tests that a digest stream can be reset multiple times (3 cycles)
	* to catch state corruption that only manifests after many iterations
	*/
	static int TestDigestMultiReset(void)
	{
		ncc_digest_t stream;
		cspan_t emptyKey;
		cspan_t data;
		uint8_t out1[SHA256_DIGEST_SIZE];
		uint8_t out2[SHA256_DIGEST_SIZE];
		uint8_t out3[SHA256_DIGEST_SIZE];
		/* "abc" */
		uint8_t buf[] = { 0x61, 0x62, 0x63 };

		uint32_t flags = NC_CRYPTO_DIGEST_TYPE_SHA256 | NC_CRYPTO_DIGEST_FLAGS_REUSE;

		spanInitC(&emptyKey, NULL, 0);
		spanInitC(&data, buf, sizeof(buf));

		ZERO_FILL(out1, sizeof(out1));
		ZERO_FILL(out2, sizeof(out2));
		ZERO_FILL(out3, sizeof(out3));

		EXPECT_TRUE(ncCryptoDigestCreate(&stream, flags));
		EXPECT_TRUE(ncCryptoDigestInit(&stream, emptyKey));

		/* Iteration 1 */
		{
			span_t outSpan;
			spanInit(&outSpan, out1, sizeof(out1));

			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, data));
			EXPECT_TRUE(ncCryptoDigestFinish(&stream, outSpan));
		}

		EXPECT_TRUE(ncCryptoDigestInit(&stream, emptyKey));

		/* Iteration 2 — must match iteration 1 */
		{
			span_t outSpan;
			spanInit(&outSpan, out2, sizeof(out2));

			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, data));
			EXPECT_TRUE(ncCryptoDigestFinish(&stream, outSpan));
		}

		EXPECT_TRUE(ncCryptoDigestInit(&stream, emptyKey));

		/* Iteration 3 — must match iterations 1 and 2 */
		{
			span_t outSpan;
			spanInit(&outSpan, out3, sizeof(out3));

			EXPECT_TRUE(ncCryptoDigestUpdate(&stream, data));
			EXPECT_TRUE(ncCryptoDigestFinish(&stream, outSpan));
		}

		ncCryptoDigestClose(&stream);

		EXPECT_EQ(memcmp(out1, out2, SHA256_DIGEST_SIZE), 0u);
		EXPECT_EQ(memcmp(out2, out3, SHA256_DIGEST_SIZE), 0u);

		return 0;
	}

	/*
	* Tests that an HMAC stream produces output
	* when Update is called with empty data (HMAC(key, ""))
	*/
	static int TestHmacEmptyData(void)
	{
		ncc_digest_t stream;
		/* RFC 4231 Test Case 1 key: 0x0b repeated 20 times */
		uint8_t keyBuf[] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
							 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
							 0x0b, 0x0b, 0x0b, 0x0b };
		cspan_t key;
		cspan_t emptyData;
		uint8_t actual[SHA256_DIGEST_SIZE];
		uint8_t zero[SHA256_DIGEST_SIZE];
		span_t outSpan;

		uint32_t flags = NC_CRYPTO_DIGEST_TYPE_SHA256 | NC_CRYPTO_DIGEST_FLAGS_HMAC;

		spanInitC(&key, keyBuf, sizeof(keyBuf));
		spanInitC(&emptyData, NULL, 0);
		spanInit(&outSpan, actual, sizeof(actual));

		ZERO_FILL(zero, sizeof(zero));

		EXPECT_TRUE(ncCryptoDigestCreate(&stream, flags));
		EXPECT_TRUE(ncCryptoDigestInit(&stream, key));

		/* Update with empty data — should produce a valid HMAC(key, "") */
		EXPECT_TRUE(ncCryptoDigestUpdate(&stream, emptyData));
		EXPECT_TRUE(ncCryptoDigestFinish(&stream, outSpan));

		ncCryptoDigestClose(&stream);

		/* Output must be non-zero (not all zeroes) */
		EXPECT_TRUE(memcmp(actual, zero, SHA256_DIGEST_SIZE) != 0);

		return 0;
	}
		
	/*
	* Tests that an HMAC stream accepts an empty key and
	* produces non-zero output (HMAC pads to block size internally)
	*/
	static int TestHmacEmptyKey(void)
	{
		ncc_digest_t stream;
		cspan_t emptyKey;
		cspan_t data;
		uint8_t actual[SHA256_DIGEST_SIZE];
		uint8_t zero[SHA256_DIGEST_SIZE];
		span_t outSpan;

		uint32_t flags = NC_CRYPTO_DIGEST_TYPE_SHA256 | NC_CRYPTO_DIGEST_FLAGS_HMAC;

		/* "abc" */
		uint8_t buf[] = { 0x61, 0x62, 0x63 };

		spanInitC(&emptyKey, NULL, 0);
		spanInitC(&data, buf, sizeof(buf));
		spanInit(&outSpan, actual, sizeof(actual));

		ZERO_FILL(zero, sizeof(zero));

		EXPECT_TRUE(ncCryptoDigestCreate(&stream, flags));
		EXPECT_TRUE(ncCryptoDigestInit(&stream, emptyKey));
		EXPECT_TRUE(ncCryptoDigestUpdate(&stream, data));
		EXPECT_TRUE(ncCryptoDigestFinish(&stream, outSpan));

		ncCryptoDigestClose(&stream);

		/* Output must be non-zero */
		EXPECT_TRUE(memcmp(actual, zero, SHA256_DIGEST_SIZE) != 0);

		return 0;
	}

	int StreamTests(void)
	{
		RUN_TEST(TestDigestInitSuccess());
		RUN_TEST(TestCloseSafeNoop());
		RUN_TEST(TestGetOutputSizeSha256());
		RUN_TEST(TestDigestResetLoop());	
		RUN_TEST(TestResetWithDifferentData());
		RUN_TEST(TestEmptyUpdateNoop());
		RUN_TEST(TestDigestMultiReset());	
		RUN_TEST(TestEmptyUpdateNoop());
		RUN_TEST(TestDigestResetDifferentData());

		RUN_TEST(TestHmacEmptyKey());
		RUN_TEST(TestHmacResetLoop());
		RUN_TEST(TestHmacEmptyData());

		return 0;
	}
#endif
