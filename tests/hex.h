/*
* Copyright (c) 2026 Vaughn Nugent
*
* Package: noscrypt
* File: hex.h
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

/*
* The helper utility functions in this header are implemented in test-base.c
*/

#ifndef HEX_HELPERS_H
#define HEX_HELPERS_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <span.h>

/* 
	Allocates a span_t and decodes the hexadecimal string into its binary
	representation. The string must be a valid hexadecimal string and the length
	and may not be NULL. The length may be known at compile time and can be used
    to assert the length of the string literal.
	@param hexLiteral The hexadecimal string to decode
	@param strLen The length of the string
*/
#define FromHexString(str, len) _fromHexString(str, sizeof(str) - 1); STATIC_ASSERT((sizeof(str) - 1)/2 == len && len > 0, "Invalid length hex string literal");

span_t _fromHexString(const char* hexLiteral, uint32_t strLen);

/*
	Frees all the span_t that were allocated by the 
	FromHexString function. To be called at the end of 
	the program.
*/
void FreeHexBytes(void);

/*
* Prints the value of the buffer as a hexadecimal string
* @param bytes The buffer to print
* @param len The length of the buffer
*/
void PrintHexRaw(void* bytes, size_t len);

/*
* Prints the value of the span_t as a hexadecimal string
* @param hexBytes A pointer to the span_t structure to print the value of
*/
void PrintHexBytes(span_t hexBytes);

#endif /* !HEX_HELPERS_H */


