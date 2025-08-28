/*
* Copyright (c) 2025 Vaughn Nugent
*
* Package: noscrypt
* File: internal-test.c
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


#include "test.h"
#include <nc-util.h>

static int UtilSpanInitAndValidityTest(void)
{
    uint8_t buf[16];
    span_t s;
    cspan_t cs;

    ncSpanInit(&s, buf, (uint32_t)sizeof(buf));
    EXPECT_EQ(ncSpanIsValid(s), 1);
    EXPECT_EQ(ncSpanGetSize(s), (uint32_t)sizeof(buf));

    ncSpanInitC(&cs, buf, (uint32_t)sizeof(buf));
    EXPECT_EQ(ncSpanIsValidC(cs), 1);
    EXPECT_EQ(ncSpanGetSizeC(cs), (uint32_t)sizeof(buf));

    /* Zero-length spans are valid when EMPTY_SPANS == 1 */
    {
        span_t zs;
        cspan_t zcs;
        ncSpanInit(&zs, NULL, 0);
        ncSpanInitC(&zcs, NULL, 0);

        EXPECT_EQ(ncSpanIsValid(zs), 1);
        EXPECT_EQ(ncSpanGetSize(zs), 0u);

        EXPECT_EQ(ncSpanIsValidC(zcs), 1);
        EXPECT_EQ(ncSpanGetSizeC(zcs), 0u);
    }

    /* Invalid spans (non-zero size, NULL data) */
    {
        span_t inv = { NULL, 4 };
        cspan_t cinv = { NULL, 4 };

        EXPECT_EQ(ncSpanIsValid(inv), 0);
        EXPECT_EQ(ncSpanGetSize(inv), 0u);

        EXPECT_EQ(ncSpanIsValidC(cinv), 0);
        EXPECT_EQ(ncSpanGetSizeC(cinv), 0u);
    }

    return 0;
}

static int UtilSpanGetAndOffsetWriteReadTest(void)
{
	uint8_t buf[32] = { 0 };

    span_t s;
    ncSpanInit(&s, buf, (uint32_t)sizeof(buf));

    /* Write pattern at offset */
    {
        const uint8_t pattern1[] = { 1, 2, 3, 4 };
        ncSpanWrite(s, 4, pattern1, (uint32_t)sizeof(pattern1));
        EXPECT_EQ(memcmp(buf + 4, pattern1, sizeof(pattern1)), 0);
    }

    /* Append data and verify offset/data */
    {
        const uint8_t a[] = { 0xAA, 0xBB, 0xCC };
        const uint8_t b[] = { 0x11, 0x22, 0x33, 0x44 };
        uint32_t off = 0;

        ncSpanAppend(s, &off, a, (uint32_t)sizeof(a));
        ncSpanAppend(s, &off, b, (uint32_t)sizeof(b));

        EXPECT_EQ(off, (uint32_t)(sizeof(a) + sizeof(b)));
        EXPECT_EQ(memcmp(buf, a, sizeof(a)), 0);
        EXPECT_EQ(memcmp(buf + sizeof(a), b, sizeof(b)), 0);
    }

    /* Offsets */
    {        
        EXPECT_TRUE(ncSpanGetOffset(s, 10) == buf + 10);      

        cspan_t cs;
        ncSpanInitC(&cs, buf, (uint32_t)sizeof(buf));

        EXPECT_TRUE(ncSpanGetOffsetC(cs, 10) == buf + 10);
    }

    /* Copy */
    {
		uint8_t dest[32] = { 0 };
        span_t d;

        ncSpanInit(&d, dest, (uint32_t)sizeof(dest));
        ncSpanCopy(s, d);

        EXPECT_EQ(memcmp(dest, buf, sizeof(buf)), 0);
    }

    /* Read (const) */
    {
		uint8_t raw[7] = { 0 };
        cspan_t slice;

        ncSpanInitC(&slice, buf + 3, (uint32_t)sizeof(raw));
        ncSpanReadC(slice, raw, (uint32_t)sizeof(raw));

        EXPECT_EQ(memcmp(raw, buf + 3, sizeof(raw)), 0);
    }

    /* Read (mutable span) */
    {
		uint8_t raw2[7] = { 0 };

        span_t sslice;
        
        ncSpanInit(&sslice, buf + 6, (uint32_t)sizeof(raw2));
        ncSpanRead(sslice, raw2, (uint32_t)sizeof(raw2));
       
        EXPECT_EQ(memcmp(raw2, buf + 6, sizeof(raw2)), 0);
    }

    return 0;
}

static int UtilSpanSliceAndRangeTest(void)
{
    uint8_t buf[64] = { 0 };

    for (uint32_t i = 0; i < (uint32_t)sizeof(buf); i++) 
    { 
        buf[i] = (uint8_t)i; 
    }

    span_t s;
    ncSpanInit(&s, buf, (uint32_t)sizeof(buf));

    /* Mutable slice */
    {
        span_t sl = ncSpanSlice(s, 8, 16);
        
        EXPECT_EQ(sl.size, 16u);
		EXPECT_EQ(ncSpanGetSize(sl), 16u);
       
        EXPECT_EQ(memcmp(sl.data, buf + 8, 16), 0);
        EXPECT_EQ(memcmp(ncSpanGetOffset(sl, 0), buf + 8, 16), 0);
    }

    /* Const slice */
    {
        cspan_t cs;
        ncSpanInitC(&cs, buf, (uint32_t)sizeof(buf));
        cspan_t csl = ncSpanSliceC(cs, 20, 10);
        
        EXPECT_EQ(csl.size, 10u);
		EXPECT_EQ(ncSpanGetSizeC(csl), 10u);
        EXPECT_EQ(memcmp(csl.data, buf + 20, 10), 0);

        /* Copy const slice to mutable destination */
		uint8_t out[10] = { 0 };
        span_t outSpan;
        
        ncSpanInit(&outSpan, out, (uint32_t)sizeof(out));
        ncSpanCopyC(csl, outSpan);
        
        EXPECT_EQ(memcmp(out, buf + 20, 10), 0);
    }

    /* Zero-size slices */
    {
        span_t z = ncSpanSlice(s, 0, 0);
        EXPECT_EQ(z.size, 0u);
        EXPECT_TRUE(z.data == (uint8_t*)NULL);

        EXPECT_EQ(ncSpanGetSize(z), 0u);
        EXPECT_TRUE(ncSpanGetOffset(z, 0) == (uint8_t*)NULL);

        cspan_t cs;
        ncSpanInitC(&cs, buf, (uint32_t)sizeof(buf));
        cspan_t zc = ncSpanSliceC(cs, 5, 0);

        EXPECT_EQ(zc.size, 0u);
        EXPECT_TRUE(zc.data == (uint8_t*)NULL);
		
		EXPECT_EQ(ncSpanGetSizeC(zc), 0u);	
		EXPECT_TRUE(ncSpanGetOffsetC(zc, 0) == (const uint8_t*)NULL);
    }

    /* Range checks */
    {
        cspan_t cs;
        ncSpanInitC(&cs, buf, (uint32_t)sizeof(buf));

        EXPECT_TRUE(ncSpanIsValidRange(s, 20, 10));
        EXPECT_FALSE(ncSpanIsValidRange(s, 60, 5));

        EXPECT_TRUE(ncSpanIsValidRangeC(cs, 64, 0)); /* at end, size 0 is valid */
        EXPECT_FALSE(ncSpanIsValidRangeC(cs, 65, 0));
    }

    return 0;
}

static int UtilEmptySpanBehaviorTest(void)
{
    uint8_t buf[8] = { 0 };

    /* Zero-length cspan with non-null data is valid */
    {
        cspan_t empty;
     
#if EMPTY_SPANS  
        /* If empty spans are allowed, the data pointer may be null */
        ncSpanInitC(&empty, NULL, 0);
#else
		ncSpanInitC(&empty, buf, 0);
#endif

        EXPECT_TRUE(ncSpanIsValidC(empty));
        EXPECT_EQ(ncSpanGetSizeC(empty), 0u);

#if EMPTY_SPANS
        /* For empty spans with offset 0, ncSpanGetOffsetC returns NULL */     
        EXPECT_TRUE(ncSpanGetOffsetC(empty, 0) == (const uint8_t*)NULL);
#endif
    }

    /* Copying empty cspan should not modify destination */
    {
		uint8_t dst[8] = { 0 };
		uint8_t expected[8] = { 0 };

        memset(dst, 0xEE, sizeof dst);       
        memset(expected, 0xEE, sizeof expected);

        cspan_t empty;
        ncSpanInitC(&empty, buf, 0);

        span_t d;
        ncSpanInit(&d, dst, (uint32_t)sizeof(dst));
        ncSpanCopyC(empty, d);

        EXPECT_EQ(memcmp(dst, expected, sizeof(dst)), 0);
    }

    /* Appending 0 bytes should not change offset */
    {
        span_t s;
        ncSpanInit(&s, buf, (uint32_t)sizeof(buf));

        uint32_t off = 3;
        ncSpanAppend(s, &off, buf, 0);

        EXPECT_EQ(off, 3u);
    }

    return 0;
}

int RunTests(void)
{
    RUN_TEST(UtilSpanInitAndValidityTest());

    RUN_TEST(UtilSpanGetAndOffsetWriteReadTest());

    RUN_TEST(UtilSpanSliceAndRangeTest());

    RUN_TEST(UtilEmptySpanBehaviorTest());

    return 0;
}