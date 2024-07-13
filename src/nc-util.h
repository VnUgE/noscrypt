
/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: nc-util.h
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

#pragma once

#ifndef _NC_UTIL_H
#define _NC_UTIL_H

#include <platform.h>

/* NULL */
#ifndef NULL
	#define NULL ((void*)0)
#endif /*  !NULL */

#ifdef DEBUG
	/* Must include assert.h for assertions */
	#include <assert.h> 
	#define DEBUG_ASSERT(x) assert(x);
	#define DEBUG_ASSERT2(x, message) assert(x && message);	

	/*
	* Compiler enabled static assertion keywords are 
	* only available in C11 and later. Later versions 
	* have macros built-in from assert.h so we can use
	* the static_assert macro directly.
	* 
	* Static assertions are only used for testing such as 
	* sanity checks and this library targets the c89 standard
	* so static_assret very likely will not be available. 
	*/
	#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
		#define STATIC_ASSERT(x, m) static_assert(x, m);
	#elif !defined(STATIC_ASSERT)
		#define STATIC_ASSERT(x, m)
		#pragma message("Static assertions are not supported by this language version")
	#endif

#else
	#define DEBUG_ASSERT(x)
	#define DEBUG_ASSERT2(x, message)
	#define STATIC_ASSERT(x, m)
#endif

#include <stdint.h>

#if SIZE_MAX < UINT32_MAX
	#define _overflow_check(x) if(x > SIZE_MAX) return CSTATUS_FAIL;
#else
	#define _overflow_check(x)
#endif

#ifdef NC_EXTREME_COMPAT

	void _nc_memmove(void* dst, const void* src, uint32_t size)
	{
		uint32_t i;

		for (i = 0; i < size; i++)
		{
			((uint8_t*)dst)[i] = ((uint8_t*)src)[i];
		}
	}

	#define MEMMOV _nc_memmove

#else

	/* Include string for memmove */
	#include <string.h>
	#define MEMMOV(dst, src, size) memmove(dst, src, size)

#endif /* NC_EXTREME_COMPAT */

typedef struct memory_span_struct
{
	uint8_t* data;
	uint32_t size;
} span_t;

typedef struct read_only_memory_span_struct
{
	const uint8_t* data;
	uint32_t size;
} cspan_t;

static _nc_fn_inline void ncSpanInitC(cspan_t* span, const uint8_t* data, uint32_t size)
{
	span->data = data;
	span->size = size;
}

static _nc_fn_inline void ncSpanInit(span_t* span, uint8_t* data, uint32_t size)
{
	span->data = data;
	span->size = size;
}

static _nc_fn_inline void ncSpanWrite(span_t span, uint32_t offset, const uint8_t* data, uint32_t size)
{
	DEBUG_ASSERT2(span.data != NULL,	"Expected span to be non-null")
	DEBUG_ASSERT2(data != NULL,			"Expected data to be non-null")
	DEBUG_ASSERT2(offset + size <= span.size, "Expected offset + size to be less than span size")

	/* Copy data to span */
	MEMMOV(span.data + offset, data, size);
}

static _nc_fn_inline void ncSpanAppend(span_t span, uint32_t* offset, const uint8_t* data, uint32_t size)
{
	DEBUG_ASSERT2(span.data != NULL,	"Expected span to be non-null")
	DEBUG_ASSERT2(offset != NULL,		"Expected offset to be non-null")
	DEBUG_ASSERT2(data != NULL,			"Expected data to be non-null")
	DEBUG_ASSERT2(*offset + size <= span.size, "Expected offset + size to be less than span size")

	/* Copy data to span */
	MEMMOV(span.data + *offset, data, size);

	/* Increment offset */
	*offset += size;
}

static _nc_fn_inline span_t ncSpanSlice(span_t span, uint32_t offset, uint32_t size)
{
	span_t slice;

	DEBUG_ASSERT2(span.data != NULL,	"Expected span to be non-null");
	DEBUG_ASSERT2(offset + size <= span.size, "Expected offset + size to be less than span size")

	/* Initialize slice, offset input data by the specified offset */
	ncSpanInit(&slice, span.data + offset, size);

	return slice;
}

static _nc_fn_inline cspan_t ncSpanSliceC(cspan_t span, uint32_t offset, uint32_t size)
{
	cspan_t slice;

	DEBUG_ASSERT2(span.data != NULL, "Expected span to be non-null");
	DEBUG_ASSERT2(offset + size <= span.size, "Expected offset + size to be less than span size")

	/* Initialize slice, offset input data by the specified offset */
	ncSpanInitC(&slice, span.data + offset, size);

	return slice;
}


#endif /* !_NC_UTIL_H */