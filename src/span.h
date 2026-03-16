/*
* Copyright (c) 2026 Vaughn Nugent
*
* Package: noscrypt
* File: span.h
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

/*
* span.h - Agnostic, self-contained span (buffer-view) library.
*
* Provides two span types:
*   span_t   - mutable view over a byte buffer
*   cspan_t  - read-only view over a byte buffer
*
* A span is a (pointer, size) pair that does not own the memory it
* points to. Validity and null-ness are orthogonal properties:
*
*   valid  = data != NULL || size == 0   (safe to operate on)
*   null   = data == NULL                (no backing memory assigned)
*
* An empty span {NULL, 0} is valid but also null. Use spanIsNull to 
* test buffer lifecycle state (e.g. whether a buffer has been allocated)
*/

#pragma once

#ifndef _SPAN_H
#define _SPAN_H

#include <stdint.h>
#include <platform.h>
#include "debug.h"

/*
* By default span copies are performed with memmove for performance.
* Define SPAN_NO_MEMMOVE to use a portable byte-by-byte loop instead,
* removing the dependency on <string.h>.
*/
#ifndef SPAN_NO_MEMMOVE
	#include <string.h>
#endif

#ifndef NULL
	#define NULL ((void*)0)
#endif


/*
	TYPES
*/

/*
* A non-owning mutable view over a writable byte buffer.
* Initialize with spanInit(). Do not modify fields directly.
*/
typedef struct memory_span_struct
{
	uint8_t* data;
	uint32_t size;
} span_t;

/*
* A non-owning read-only view over a byte buffer.
* Initialize with spanInitC(). Convert from a span_t with spanToC().
*/
typedef struct read_only_memory_span_struct
{
	const uint8_t* data;
	uint32_t size;
} cspan_t;


/*
	CONSTRUCTION
*/

/*
* Initializes a mutable span from a raw pointer and byte count.
* @param span A pointer to the span structure to initialize
* @param data A pointer to the backing buffer, or NULL for an empty span
* @param size The number of bytes in the buffer
*/
static _nc_fn_inline void spanInit(span_t* span, uint8_t* data, uint32_t size)
{
	span->data = data;
	span->size = size;

	DEBUG_ASSERT2(data != NULL || size == 0, "Invalid span init: non-empty spans must have a non-null data pointer");
}

/*
* Initializes a read-only span from a raw const pointer and byte count.
* @param span A pointer to the span structure to initialize
* @param data A pointer to the backing buffer, or NULL for an empty span
* @param size The number of bytes in the buffer
*/
static _nc_fn_inline void spanInitC(cspan_t* span, const uint8_t* data, uint32_t size)
{
	span->data = data;
	span->size = size;

	DEBUG_ASSERT2(data != NULL || size == 0, "Invalid span init: non-empty spans must have a non-null data pointer");
}

/*
* Returns a read-only view of a mutable span without copying any data.
* @param span The mutable span to convert
* @return A cspan_t pointing to the same memory region
*/
static _nc_fn_inline cspan_t spanToC(span_t span)
{
	cspan_t cs;
	spanInitC(&cs, span.data, span.size);
	return cs;
}


/*
	PREDICATES
*/

/*
* Test's the internal data pointer for nullness. 
* @param span The span to test
* @return Non-zero if data is NULL, zero otherwise
*/
static _nc_fn_inline int spanIsNull(span_t span)
{
	return span.data == NULL;
}

/*
* Read-only equivalent of spanIsNull.
* @param span The span to test
* @return Non-zero if data is NULL, zero otherwise
*/
static _nc_fn_inline int spanIsNullC(cspan_t span)
{
	return span.data == NULL;
}

/*
* Returns non-zero if the span contains zero bytes, regardless of
whether a backing pointer is present.
* @param span The span to test
* @return Non-zero if size is zero, zero otherwise
*/
static _nc_fn_inline int spanIsEmpty(span_t span)
{
	return span.size == 0;
}

/*
* Read-only equivalent of spanIsEmpty.
* @param span The span to test
* @return Non-zero if size is zero, zero otherwise
*/
static _nc_fn_inline int spanIsEmptyC(cspan_t span)
{
	return span.size == 0;
}

/*
* Returns non-zero if the sub-range [offset, offset+size) lies entirely
within the span. An empty sub-range (size == 0) at offset 0 is
considered valid for any valid span.
* @param span The span to test against
* @param offset The start of the sub-range in bytes
* @param size The length of the sub-range in bytes
* @return Non-zero if the range is in bounds, zero otherwise
*/
static _nc_fn_inline int spanIsValidRange(span_t span, uint32_t offset, uint32_t size)
{
	return offset <= span.size && size <= span.size - offset;
}

/*
* Read-only equivalent of spanIsValidRange.
* @param span The span to test against
* @param offset The start of the sub-range in bytes
* @param size The length of the sub-range in bytes
* @return Non-zero if the range is in bounds, zero otherwise
*/
static _nc_fn_inline int spanIsValidRangeC(cspan_t span, uint32_t offset, uint32_t size)
{
	return offset <= span.size && size <= span.size - offset;
}


/*
	ACCESSORS
*/

/*
* Returns the number of bytes in the span, or 0 if the span is invalid.
* @param span The span to query
* @return The span size in bytes, or 0 if invalid
*/
static _nc_fn_inline uint32_t spanGetSize(span_t span)
{
	return span.size;
}

/*
* Read-only equivalent of spanGetSize.
* @param span The span to query
* @return The span size in bytes, or 0 if invalid
*/
static _nc_fn_inline uint32_t spanGetSizeC(cspan_t span)
{
	return span.size;
}

/*
* Returns a const pointer to the byte at the given offset within the span.
Returns NULL when the span is empty and offset is 0, so callers may
safely pass an empty span without risking a null dereference. The offset
must be strictly less than span.size for any non-empty span.
* @param span The span to index into
* @param offset The byte offset from the start of the span
* @return A pointer to span.data + offset, or NULL for an empty span at offset 0
*/
static _nc_fn_inline const uint8_t* spanGetOffsetC(cspan_t span, uint32_t offset)
{
	/* Safe null pass-through for empty spans at offset 0 */
	if (span.size == 0 && offset == 0)
	{
		return NULL;
	}

	return span.data + offset;
}

/*
* Mutable equivalent of spanGetOffsetC.
* @param span The span to index into
* @param offset The byte offset from the start of the span
* @return A pointer to span.data + offset, or NULL for an empty span at offset 0
*/
static _nc_fn_inline uint8_t* spanGetOffset(span_t span, uint32_t offset)
{
	return (uint8_t*)spanGetOffsetC(spanToC(span), offset);
}


/*
	SLICING
*/

/*
* Returns a mutable sub-span covering [offset, offset+size) of the source
span. A zero-length slice always produces an empty span {NULL, 0}. The
caller is responsible for ensuring the range is within bounds.
* @param span The source span to slice
* @param offset The start of the slice in bytes from the span origin
* @param size The number of bytes in the slice
* @return A span_t covering the requested sub-range
*/
static _nc_fn_inline span_t spanSlice(span_t span, uint32_t offset, uint32_t size)
{
	span_t slice;

	if (size == 0)
	{
		spanInit(&slice, NULL, 0);
	}
	else
	{
		spanInit(&slice, spanGetOffset(span, offset), size);
	}

	return slice;
}

/*
* Read-only equivalent of spanSlice.
* @param span The source span to slice
* @param offset The start of the slice in bytes from the span origin
* @param size The number of bytes in the slice
* @return A cspan_t covering the requested sub-range
*/
static _nc_fn_inline cspan_t spanSliceC(cspan_t span, uint32_t offset, uint32_t size)
{
	cspan_t slice;

	if (size == 0)
	{
		spanInitC(&slice, NULL, 0);
	}
	else
	{
		spanInitC(&slice, spanGetOffsetC(span, offset), size);
	}

	return slice;
}


/*
	DATA TRANSFER
*/

/*
* Copies src.size bytes from src into dest starting at dest.data.
src.size must be <= dest.size. A zero-size copy is a no-op.
* @param src The source read-only span
* @param dest The destination mutable span
*/
static _nc_fn_inline void spanCopyC(cspan_t src, span_t dest)
{
	if (src.size == 0)
	{
		return;
	}

	DEBUG_ASSERT2(src.data != NULL,		"spanCopyC: source data pointer is NULL")
	DEBUG_ASSERT2(dest.data != NULL,	"spanCopyC: destination data pointer is NULL")
	DEBUG_ASSERT2(dest.size >= src.size,"spanCopyC: destination buffer is smaller than source")

#ifdef _NC_IS_WINDOWS

	/*
	* Use memmove_s on Windows, forwarding dest.size as the destination
	* buffer capacity for runtime overrun detection.
	*/
	memmove_s(dest.data, dest.size, src.data, src.size);

#elif defined(SPAN_NO_MEMMOVE)
	/*
	* Portable byte-by-byte fallback — no <string.h> dependency.
	*/
	{
		uint32_t i;
		for (i = 0; i < src.size; i++)
		{
			dest.data[i] = src.data[i];
		}
	}
#else
	memmove(dest.data, src.data, src.size);
#endif
}

/*
* Copies the full contents of src into dest. src.size must be <= dest.size.
* @param src The source mutable span
* @param dest The destination mutable span
*/
static _nc_fn_inline void spanCopy(span_t src, span_t dest)
{
	spanCopyC(spanToC(src), dest);
}

/*
* Copies size bytes out of src into the raw buffer pointed to by dest.
* @param src The source read-only span
* @param dest A pointer to the destination buffer
* @param size The number of bytes to copy
*/
static _nc_fn_inline void spanReadC(cspan_t src, uint8_t* dest, uint32_t size)
{
	span_t dsts;
	spanInit(&dsts, dest, size);
	spanCopyC(src, dsts);
}

/*
* Mutable equivalent of spanReadC.
* @param src The source mutable span
* @param dest A pointer to the destination buffer
* @param size The number of bytes to copy
*/
static _nc_fn_inline void spanRead(span_t src, uint8_t* dest, uint32_t size)
{
	spanReadC(spanToC(src), dest, size);
}

/*
* Copies size bytes from the raw buffer pointed to by data into span
starting at the given byte offset. offset + size must not exceed
span.size. A zero-size write is a no-op.
* @param span The destination span
* @param offset The byte offset within the span to begin writing
* @param data A pointer to the source buffer
* @param size The number of bytes to write
*/
static _nc_fn_inline void spanWrite(span_t span, uint32_t offset, const uint8_t* data, uint32_t size)
{
	cspan_t src;

	if (size == 0)
	{
		return;
	}

	DEBUG_ASSERT2(data != NULL, "spanWrite: source data pointer is NULL");
	DEBUG_ASSERT2(!spanIsNull(span), "spanWrite: destination span is null");
	DEBUG_ASSERT2(spanIsValidRange(span, offset, size), "spanWrite: write range is out of bounds");	

	spanInitC(&src, data, size);
	spanCopyC(src, spanSlice(span, offset, size));
}

/*
* Copies size bytes from data into span at *offset then advances *offset
by size, providing a simple cursor pattern for building payloads in-place.
* @param span The destination span
* @param offset A pointer to the current write cursor, updated after the write
* @param data A pointer to the source buffer
* @param size The number of bytes to append
*/
static _nc_fn_inline void spanAppend(span_t span, uint32_t* offset, const uint8_t* data, uint32_t size)
{
	spanWrite(span, *offset, data, size);
	*offset += size;
}


#endif /* !_SPAN_H */
