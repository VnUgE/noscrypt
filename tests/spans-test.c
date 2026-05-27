/*
* Copyright (c) 2026 Vaughn Nugent
*
* Package: noscrypt
* File: spans-test.c
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


#include <span.h>
#include "test.h"

static int UtilSpanInitAndValidityTest(void)
{
    /* non-empty span checks */
    {
        uint8_t buf[16];

        span_t s;
        spanInit(&s, buf, (uint32_t)sizeof(buf));

        EXPECT_FALSE(spanIsEmpty(s));
        EXPECT_FALSE(spanIsNull(s));
        EXPECT_EQ(spanGetSize(s), (uint32_t)sizeof(buf));

        cspan_t cs;
        spanInitC(&cs, buf, (uint32_t)sizeof(buf));
        
        EXPECT_FALSE(spanIsEmptyC(cs));
        EXPECT_FALSE(spanIsNullC(cs));
        EXPECT_EQ(spanGetSizeC(cs), (uint32_t)sizeof(buf));
    }

    /* Zero-length empty-null span {NULL, 0} */
    {
        span_t zs;       
        spanInit(&zs, NULL, 0);

        EXPECT_TRUE(spanIsEmpty(zs));
        EXPECT_TRUE(spanIsNull(zs));
        EXPECT_EQ(spanGetSize(zs), 0u);

        cspan_t zcs;
        spanInitC(&zcs, NULL, 0);

        EXPECT_TRUE(spanIsEmptyC(zcs));
        EXPECT_TRUE(spanIsNullC(zcs));
        EXPECT_EQ(spanGetSizeC(zcs), 0u);
    }

    /* Invalid spans (non-zero size, NULL data) */
    {
        span_t inv = { NULL, 4 };      

        /* should not be empty, but null */
        EXPECT_FALSE(spanIsEmpty(inv));
        EXPECT_TRUE(spanIsNull(inv));
        EXPECT_EQ(spanGetSize(inv), 4u);

        cspan_t cinv = { NULL, 4 };

        EXPECT_FALSE(spanIsEmptyC(cinv));
        EXPECT_TRUE(spanIsNullC(cinv));
        EXPECT_EQ(spanGetSizeC(cinv), 4u);
    }

    /* Zero-length span with non-null data: empty but not null */
    {
        uint8_t buf[8];

        span_t zs;
        spanInit(&zs, buf, 0);

        EXPECT_TRUE(spanIsEmpty(zs));
        EXPECT_FALSE(spanIsNull(zs));
        EXPECT_EQ(spanGetSize(zs), 0u);

        cspan_t zcs;
        spanInitC(&zcs, buf, 0);

        EXPECT_TRUE(spanIsEmptyC(zcs));
        EXPECT_FALSE(spanIsNullC(zcs));
        EXPECT_EQ(spanGetSizeC(zcs), 0u);
    }

    return 0;
}

static int SpanToCConversionTest(void)
{
    uint8_t buf[16];

    /* spanToC preserves the data pointer and size exactly */
    {
        span_t s;
        spanInit(&s, buf, (uint32_t)sizeof(buf));

        cspan_t cs = spanToC(s);

        EXPECT_TRUE(cs.data == buf);
        EXPECT_EQ(cs.size, (uint32_t)sizeof(buf));
        EXPECT_FALSE(spanIsNullC(cs));
        EXPECT_FALSE(spanIsEmptyC(cs));
    }

    /* spanToC on empty span produces an empty cspan */
    {
        span_t empty;
        spanInit(&empty, NULL, 0);

        cspan_t cempty = spanToC(empty);

        EXPECT_TRUE(spanIsNullC(cempty));
        EXPECT_TRUE(spanIsEmptyC(cempty));
        EXPECT_EQ(spanGetSizeC(cempty), 0u);
    }

    /* spanToC on non-null zero-size span preserves pointer */
    {
        span_t zs;
        spanInit(&zs, buf, 0);

        cspan_t czs = spanToC(zs);

        EXPECT_TRUE(czs.data == buf);
        EXPECT_TRUE(spanIsEmptyC(czs));
        EXPECT_FALSE(spanIsNullC(czs));
    }

    return 0;
}

static int SpanWriteTest(void)
{
    /* Again, tests rely on the size of this buffer to avoid overruns */
    uint8_t buf[32] = { 0 };

    span_t s;
    spanInit(&s, buf, (uint32_t)sizeof(buf));

    /* Write at offset 0 */
    {
        const uint8_t data[] = { 0xAA, 0xBB, 0xCC, 0xDD };
        spanWrite(s, 0, data, (uint32_t)sizeof(data));
        EXPECT_EQ(memcmp(buf, data, sizeof(data)), 0);
    }

    /* Write at non-zero offset */
    {
        const uint8_t pattern[] = { 1, 2, 3, 4 };
        spanWrite(s, 4, pattern, (uint32_t)sizeof(pattern));
        EXPECT_EQ(memcmp(buf + 4, pattern, sizeof(pattern)), 0);
    }

    /* Write at end boundary: offset + size == span.size */
    {
        const uint8_t tail[] = { 0x11, 0x22, 0x33, 0x44 };
        spanWrite(s, 28, tail, (uint32_t)sizeof(tail));
        EXPECT_EQ(memcmp(buf + 28, tail, sizeof(tail)), 0);
    }

    /* Multiple successive writes do not corrupt each other */
    {
        uint8_t buf2[16] = { 0 };
        span_t s2;
        spanInit(&s2, buf2, (uint32_t)sizeof(buf2));

        const uint8_t a[] = { 1, 2, 3, 4 };
        const uint8_t b[] = { 5, 6, 7, 8 };
        spanWrite(s2, 0, a, (uint32_t)sizeof(a));
        spanWrite(s2, 4, b, (uint32_t)sizeof(b));

        EXPECT_EQ(memcmp(buf2, a, sizeof(a)), 0);
        EXPECT_EQ(memcmp(buf2 + 4, b, sizeof(b)), 0);
    }

    /* Zero-size write at offset > 0 is a no-op */
    {
        uint8_t buf3[8] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
        span_t s3;
        spanInit(&s3, buf3, (uint32_t)sizeof(buf3));

        const uint8_t data[] = { 0xFF, 0xFF };
        spanWrite(s3, 4, data, 0);

        /* Buffer must be untouched */
        uint8_t expected[8] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
        EXPECT_EQ(memcmp(buf3, expected, sizeof(buf3)), 0);
    }

    return 0;
}

static int SpanAppendTest(void)
{
    uint8_t buf[16] = { 0 };
    span_t s;
    spanInit(&s, buf, (uint32_t)sizeof(buf));

    /* Sequential appends track the cursor correctly */
    {
        const uint8_t a[] = { 0xAA, 0xBB, 0xCC };
        const uint8_t b[] = { 0x11, 0x22, 0x33, 0x44 };
        uint32_t off = 0;

        spanAppend(s, &off, a, (uint32_t)sizeof(a));
        spanAppend(s, &off, b, (uint32_t)sizeof(b));

        EXPECT_EQ(off, (uint32_t)(sizeof(a) + sizeof(b)));
        EXPECT_EQ(memcmp(buf, a, sizeof(a)), 0);
        EXPECT_EQ(memcmp(buf + sizeof(a), b, sizeof(b)), 0);
    }

    /* Sequential appends fill the entire span exactly */
    {
        uint8_t buf2[8] = { 0 };
        span_t s2;
        spanInit(&s2, buf2, (uint32_t)sizeof(buf2));

        const uint8_t first[4]  = { 1, 2, 3, 4 };
        const uint8_t second[4] = { 5, 6, 7, 8 };
        uint32_t off = 0;

        spanAppend(s2, &off, first,  (uint32_t)sizeof(first));
        spanAppend(s2, &off, second, (uint32_t)sizeof(second));

        EXPECT_EQ(off, 8u);
        EXPECT_EQ(memcmp(buf2,     first,  sizeof(first)),  0);
        EXPECT_EQ(memcmp(buf2 + 4, second, sizeof(second)), 0);
    }

    /* Cursor starts from a non-zero offset */
    {
        uint8_t buf3[8] = { 0 };
        span_t s3;
        spanInit(&s3, buf3, (uint32_t)sizeof(buf3));

        const uint8_t data[] = { 0xDE, 0xAD };
        uint32_t off = 4;

        spanAppend(s3, &off, data, (uint32_t)sizeof(data));

        EXPECT_EQ(off, 6u);
        EXPECT_EQ(memcmp(buf3 + 4, data, sizeof(data)), 0);
    }

    return 0;
}

static int SpanOffsetTest(void)
{
    uint8_t buf[32];
   
    for (uint32_t i = 0; i < (uint32_t)sizeof(buf); i++)
    { 
        buf[i] = (uint8_t)i; 
    }

    span_t s;
    spanInit(&s, buf, (uint32_t)sizeof(buf));

    /* spanGetOffset: mid-span */
    EXPECT_TRUE(spanGetOffset(s, 10) == buf + 10);

    /* spanGetOffset: offset 0 */
    EXPECT_TRUE(spanGetOffset(s, 0) == buf);

    /* spanGetOffset: last valid index */
    EXPECT_TRUE(spanGetOffset(s, 31) == buf + 31);

    /* spanGetOffsetC equivalents */
    {
        cspan_t cs;
        spanInitC(&cs, buf, (uint32_t)sizeof(buf));

        EXPECT_TRUE(spanGetOffsetC(cs, 10) == buf + 10);
        EXPECT_TRUE(spanGetOffsetC(cs, 0)  == buf);
        EXPECT_TRUE(spanGetOffsetC(cs, 31) == buf + 31);
    }

    /* Offset 0 on an empty span returns NULL */
    {
        span_t empty;
        spanInit(&empty, NULL, 0);
        EXPECT_TRUE(spanGetOffset(empty, 0) == (uint8_t*)NULL);

        cspan_t cempty;
        spanInitC(&cempty, NULL, 0);
        EXPECT_TRUE(spanGetOffsetC(cempty, 0) == (const uint8_t*)NULL);
    }

    return 0;
}

static int SpanCopyTest(void)
{
    /* spanCopy: full mutable-to-mutable copy */
    {
        uint8_t src_buf[32];
        uint8_t dst_buf[32] = { 0 };  
        
        for (uint32_t i = 0; i < 32u; i++)
        { 
            src_buf[i] = (uint8_t)i; 
        }

        span_t src, dst;
        spanInit(&src, src_buf, 32u);
        spanInit(&dst, dst_buf, 32u);
        spanCopy(src, dst);

        EXPECT_EQ(memcmp(dst_buf, src_buf, 32), 0);
    }

    /* spanCopyC: exact-size copy (src.size == dest.size) */
    {
        uint8_t src_buf[16] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
                                0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00 };
        uint8_t dst_buf[16] = { 0 };

        cspan_t src;
        span_t dst;
        spanInitC(&src, src_buf, 16u);
        spanInit(&dst, dst_buf, 16u);
        spanCopyC(src, dst);

        EXPECT_EQ(memcmp(dst_buf, src_buf, 16), 0);
    }

    /* spanCopyC: overlapping buffers — validates memmove semantics */
    {
        uint8_t buf[32];        

        for (uint32_t i = 0; i < 32u; i++)
        { 
            buf[i] = (uint8_t)i; 
        }

        /* src = buf[0..15], dst = buf[8..23] — 8-byte overlap */
        cspan_t src;
        span_t dst;
        spanInitC(&src, buf,     16u);
        spanInit(&dst,  buf + 8, 16u);
        spanCopyC(src, dst);

        /* buf[8..23] should now contain original buf[0..15] = [0..15] */
        uint8_t expected[16];

        for (uint32_t i = 0; i < 16u; i++)
        { 
            expected[i] = (uint8_t)i; 
        }

        EXPECT_EQ(memcmp(buf + 8, expected, 16), 0);
    }

    /* spanCopyC: forward overlap (dst before src) — the case memcpy would corrupt */
    {
        uint8_t buf[32];

        for (uint32_t i = 0; i < 32u; i++)
        {
            buf[i] = (uint8_t)i;
        }

        /* dst = buf[0..15], src = buf[8..23] — 8-byte forward overlap */
        cspan_t src;
        span_t dst;
        spanInitC(&src, buf + 8, 16u);
        spanInit(&dst,  buf,     16u);
        spanCopyC(src, dst);

        /* buf[0..15] should now contain original buf[8..23] = [8..23] */
        uint8_t expected[16];

        for (uint32_t i = 0; i < 16u; i++)
        {
            expected[i] = (uint8_t)(i + 8);
        }

        EXPECT_EQ(memcmp(buf, expected, 16), 0);
    }

    /* spanCopyC: partial copy (src.size < dest.size) leaves trailing bytes untouched */
    {
        uint8_t src_buf[8];
        uint8_t dst_buf[16];

        for (uint32_t i = 0; i < 8u; i++)
        {
            src_buf[i] = (uint8_t)(i + 0xA0);
        }

        memset(dst_buf, 0xEE, sizeof dst_buf);

        cspan_t src;
        span_t dst;
        spanInitC(&src, src_buf, 8u);
        spanInit(&dst, dst_buf, 16u);
        spanCopyC(src, dst);

        /* First 8 bytes must match source */
        EXPECT_EQ(memcmp(dst_buf, src_buf, 8), 0);
        /* Trailing 8 bytes must remain untouched */
        uint8_t trailing[8];
        memset(trailing, 0xEE, sizeof trailing);
        EXPECT_EQ(memcmp(dst_buf + 8, trailing, 8), 0);
    }

    return 0;
}

static int SpanReadTest(void)
{
    /* Buffer size must be large enough to slice during read, do not shrink. */
    uint8_t src_buf[16];

    for (uint32_t i = 0; i < 16u; i++) 
    { 
        src_buf[i] = (uint8_t)(i + 1);
    }

    /* spanReadC: read from const span into raw buffer */
    {
		
        uint8_t out[7] = { 0 };
        cspan_t slice;
        spanInitC(&slice, src_buf + 3, (uint32_t)sizeof(out));
        spanReadC(slice, out, (uint32_t)sizeof(out));

        EXPECT_EQ(memcmp(out, src_buf + 3, sizeof(out)), 0);
    }

    /* spanRead: read from mutable span into raw buffer */
    {
        uint8_t out[7] = { 0 };
        span_t slice;
        spanInit(&slice, src_buf + 6, (uint32_t)sizeof(out));
        spanRead(slice, out, (uint32_t)sizeof(out));

        EXPECT_EQ(memcmp(out, src_buf + 6, sizeof(out)), 0);
    }

    /* Zero-size read is a no-op — destination unchanged */
    {
        uint8_t out[4] = { 0xCC, 0xCC, 0xCC, 0xCC };
        cspan_t empty;
        spanInitC(&empty, src_buf, 0);
        spanReadC(empty, out, 0);

        uint8_t expected[4] = { 0xCC, 0xCC, 0xCC, 0xCC };
        EXPECT_EQ(memcmp(out, expected, sizeof(out)), 0);
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
    spanInit(&s, buf, (uint32_t)sizeof(buf));

    /* Mutable slice */
    {
        span_t sl = spanSlice(s, 8, 16);
        
        EXPECT_EQ(sl.size, 16u);
        EXPECT_EQ(spanGetSize(sl), 16u);
       
        EXPECT_EQ(memcmp(sl.data, buf + 8, 16), 0);
        EXPECT_EQ(memcmp(spanGetOffset(sl, 0), buf + 8, 16), 0);
    }

    /* Const slice */
    {
        cspan_t cs;
        spanInitC(&cs, buf, (uint32_t)sizeof(buf));
        cspan_t csl = spanSliceC(cs, 20, 10);
        
        EXPECT_EQ(csl.size, 10u);
        EXPECT_EQ(spanGetSizeC(csl), 10u);
        EXPECT_EQ(memcmp(csl.data, buf + 20, 10), 0);

        /* Copy const slice to mutable destination */
        uint8_t out[10] = { 0 };
        span_t outSpan;
        
        spanInit(&outSpan, out, (uint32_t)sizeof(out));
        spanCopyC(csl, outSpan);
        
        EXPECT_EQ(memcmp(out, buf + 20, 10), 0);
    }

    /* Zero-size slices */
    {
        span_t z = spanSlice(s, 0, 0);
        EXPECT_EQ(z.size, 0u);
        EXPECT_TRUE(z.data == (uint8_t*)NULL);

        EXPECT_EQ(spanGetSize(z), 0u);
        EXPECT_TRUE(spanGetOffset(z, 0) == (uint8_t*)NULL);

        cspan_t cs;
        spanInitC(&cs, buf, (uint32_t)sizeof(buf));
        cspan_t zc = spanSliceC(cs, 5, 0);

        EXPECT_EQ(zc.size, 0u);
        EXPECT_TRUE(zc.data == (uint8_t*)NULL);

        EXPECT_EQ(spanGetSizeC(zc), 0u);
        EXPECT_TRUE(spanGetOffsetC(zc, 0) == (const uint8_t*)NULL);
    }

    return 0;
}

static int SpanSliceBoundaryTest(void)
{
    uint8_t buf[32];

    for (uint32_t i = 0; i < 32u; i++) 
    { 
        buf[i] = (uint8_t)i; 
    }

    span_t s;
    spanInit(&s, buf, (uint32_t)sizeof(buf));

    /* Slice at offset 0 with size > 0 */
    {
        span_t sl = spanSlice(s, 0, 8);
        EXPECT_EQ(spanGetSize(sl), 8u);
        EXPECT_TRUE(sl.data == buf);
        EXPECT_EQ(memcmp(sl.data, buf, 8), 0);
    }

    /* Slice at trailing boundary: offset + size == span.size */
    {
        span_t sl = spanSlice(s, 24, 8);
        EXPECT_EQ(spanGetSize(sl), 8u);
        EXPECT_TRUE(sl.data == buf + 24);
        EXPECT_EQ(memcmp(sl.data, buf + 24, 8), 0);
    }

    /* Nested slice: slice of a slice */
    {
        span_t outer = spanSlice(s, 8, 16);     /* buf[8..23] */
        span_t inner = spanSlice(outer, 4, 8);  /* buf[12..19] */

        EXPECT_EQ(spanGetSize(inner), 8u);
        EXPECT_TRUE(inner.data == buf + 12);
        EXPECT_EQ(memcmp(inner.data, buf + 12, 8), 0);
    }

    /* Const equivalents */
    {
        cspan_t cs;
        spanInitC(&cs, buf, (uint32_t)sizeof(buf));

        cspan_t sl0 = spanSliceC(cs, 0, 8);
        EXPECT_EQ(spanGetSizeC(sl0), 8u);
        EXPECT_TRUE(sl0.data == buf);

        cspan_t sle = spanSliceC(cs, 24, 8);
        EXPECT_EQ(spanGetSizeC(sle), 8u);
        EXPECT_TRUE(sle.data == buf + 24);

        /* Nested const slice */
        cspan_t outer = spanSliceC(cs, 8, 16);
        cspan_t inner = spanSliceC(outer, 4, 8);
        EXPECT_EQ(spanGetSizeC(inner), 8u);
        EXPECT_TRUE(inner.data == buf + 12);
    }

    return 0;
}

static int UtilEmptySpanBehaviorTest(void)
{
    uint8_t buf[8] = { 0 };

    /* Zero-length cspan with non-null data is valid */
    {
        cspan_t empty;

        spanInitC(&empty, NULL, 0);

        EXPECT_TRUE(spanIsNullC(empty));
        EXPECT_TRUE(spanIsEmptyC(empty));
        EXPECT_EQ(spanGetSizeC(empty), 0u);
        EXPECT_TRUE(spanGetOffsetC(empty, 0) == (const uint8_t*)NULL);
    }

    /* Copying empty cspan should not modify destination */
    {
        uint8_t dst[8] = { 0 };
        uint8_t expected[8] = { 0 };

        memset(dst, 0xEE, sizeof dst);       
        memset(expected, 0xEE, sizeof expected);

        cspan_t empty;
        spanInitC(&empty, buf, 0);

        span_t d;
        spanInit(&d, dst, (uint32_t)sizeof(dst));
        spanCopyC(empty, d);

        EXPECT_EQ(memcmp(dst, expected, sizeof(dst)), 0);
    }

    /* Copying from a null-data zero-size span {NULL, 0} must be a no-op */
    {
        uint8_t dst[8];

        memset(dst, 0xCC, sizeof dst);

        cspan_t null_src;
        spanInitC(&null_src, NULL, 0);

        span_t d;
        spanInit(&d, dst, (uint32_t)sizeof(dst));
        spanCopyC(null_src, d);

        uint8_t expected[8];
        memset(expected, 0xCC, sizeof expected);
        EXPECT_EQ(memcmp(dst, expected, sizeof(dst)), 0);
    }

    /* Appending 0 bytes should not change offset */
    {
        span_t s;
        spanInit(&s, buf, (uint32_t)sizeof(buf));

        uint32_t off = 3;
        spanAppend(s, &off, buf, 0);

        EXPECT_EQ(off, 3u);
    }

    /* Writing zero bytes to empty span should be safe */
    {
        span_t empty;
        spanInit(&empty, NULL, 0);

        const uint8_t data[] = { 1, 2, 3 };
        spanWrite(empty, 0, data, 0);  /* Should not crash */
    }

    return 0;
}

static int UtilSpanRangeOverflowTest(void)
{
    uint8_t buf[64] = { 0 };
    span_t s;
    cspan_t cs;

    spanInit(&s, buf, (uint32_t)sizeof(buf));
    spanInitC(&cs, buf, (uint32_t)sizeof(buf));

    /* Basic in-bounds and out-of-bounds range checks */
    {
        EXPECT_TRUE(spanIsValidRange(s, 20, 10));
        EXPECT_FALSE(spanIsValidRange(s, 60, 5));

        EXPECT_TRUE(spanIsValidRangeC(cs, 64, 0));  /* at end, size 0 is valid */
        EXPECT_FALSE(spanIsValidRangeC(cs, 65, 0));
    }

    /* Test overflow protection: offset + size would overflow uint32_t */
    {
        uint32_t large_offset = 0xFFFFFFF0u;  /* Close to UINT32_MAX */
        uint32_t large_size = 0x20u;          /* Would overflow when added */

        /* These should return false due to overflow protection */
        EXPECT_FALSE(spanIsValidRange(s, large_offset, large_size));
        EXPECT_FALSE(spanIsValidRangeC(cs, large_offset, large_size));
    }

    /* Test boundary condition: exact overflow at UINT32_MAX */
    {
        uint32_t max_offset = UINT32_MAX;
        uint32_t any_size = 1;

        EXPECT_FALSE(spanIsValidRange(s, max_offset, any_size));
        EXPECT_FALSE(spanIsValidRangeC(cs, max_offset, any_size));
    }

    /* Test valid boundary: end exactly at span size */
    {
        EXPECT_TRUE(spanIsValidRange(s, 0, 64));
        EXPECT_TRUE(spanIsValidRange(s, 64, 0));
        EXPECT_TRUE(spanIsValidRange(s, 32, 32));
        
        EXPECT_TRUE(spanIsValidRangeC(cs, 0, 64));
        EXPECT_TRUE(spanIsValidRangeC(cs, 64, 0));
        EXPECT_TRUE(spanIsValidRangeC(cs, 32, 32));
    }

    /* Test invalid boundary: offset or size exceeds span */
    {
        EXPECT_FALSE(spanIsValidRange(s, 65, 0));   /* offset > size */
        EXPECT_FALSE(spanIsValidRange(s, 0, 65));   /* size > span.size */
        EXPECT_FALSE(spanIsValidRange(s, 32, 33));  /* offset + size > span.size */
        
        EXPECT_FALSE(spanIsValidRangeC(cs, 65, 0));
        EXPECT_FALSE(spanIsValidRangeC(cs, 0, 65));
        EXPECT_FALSE(spanIsValidRangeC(cs, 32, 33));
    }

    /* Test edge case: both offset and size at limit */
    {
        EXPECT_FALSE(spanIsValidRange(s, UINT32_MAX, UINT32_MAX));
        EXPECT_FALSE(spanIsValidRangeC(cs, UINT32_MAX, UINT32_MAX));
    }

    return 0;
}

int RunTests(void)
{
    /* Predicates and initialization */
    RUN_TEST(UtilSpanInitAndValidityTest());
    RUN_TEST(SpanToCConversionTest());

    /* Offset access */
    RUN_TEST(SpanOffsetTest());

    /* Data transfer */
    RUN_TEST(SpanWriteTest());
    RUN_TEST(SpanAppendTest());
    RUN_TEST(SpanCopyTest());
    RUN_TEST(SpanReadTest());

    /* Slicing */
    RUN_TEST(UtilSpanSliceAndRangeTest());
    RUN_TEST(SpanSliceBoundaryTest());

    /* Empty span behaviors */
    RUN_TEST(UtilEmptySpanBehaviorTest());

    /* Range validation and overflow */
    RUN_TEST(UtilSpanRangeOverflowTest());

    return 0;
}