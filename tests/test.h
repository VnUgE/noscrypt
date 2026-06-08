/*
* Copyright (c) 2026 Vaughn Nugent
*
* Package: noscrypt
* File: test.h
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
*  TEST HELPER HEADER
* 
* Contains macros and functions to assist with testing across multiple 
* test projects.
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <noscrypt.h>

#ifdef _NC_IS_WINDOWS
	#define IS_WINDOWS
#endif

#ifdef IS_WINDOWS
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
#endif

#ifdef IS_WINDOWS
    /*Asserts that an internal test condition is true, otherwise aborts the test process*/
    #define TASSERT(x) if(!(x)) { printf("ERROR! Internal test assumption failed: %s. @ Line: %d\n Aborting tests...\n", #x, __LINE__); ExitProcess(1); }
#else
    /*Asserts that an internal test condition is true, otherwise aborts the test process*/
	#define TASSERT(x) if(!(x)) { printf("ERROR! Internal test assumption failed: %s. @ Line: %d\n Aborting tests...\n", #x, __LINE__); exit(1); }
#endif

/*Prints a string literal to the console*/
#define PRINTL(x) puts(x); puts("\n");
#define ENSURE(x) if(!(x)) { printf("Test assumption failed on line %d\n", __LINE__); return 1; } 

#define EXPECT_THAT(message, bool_expr) printf("\tTesting %s [%s:%d]\n", #bool_expr, __FILE__, __LINE__); \
if(!(bool_expr))\
{ printf("FAILED: %s @ callsite %s. Line: %d \n", message, #bool_expr, __LINE__); return 1; }

#define EXPECT_EQ(x, expected) printf("\tTesting %s == %s [%s:%d]\n", #x, #expected, __FILE__, __LINE__); if(((long)x) != ((long)expected)) \
{ printf("FAILED: Expected %ld but got %ld @ callsite %s. Line: %d \n", ((long)expected), ((long)x), #x, __LINE__); return 1; }

#define EXPECT_TRUE(x) EXPECT_THAT("Expected true", (x))
#define EXPECT_FALSE(x) EXPECT_THAT("Expected false", !(x))

#define TEST EXPECT_EQ

#ifdef IS_WINDOWS
    #define ZERO_FILL(x, size) SecureZeroMemory(x, size)
#else
	#define ZERO_FILL(x, size) memset(x, 0, size)
#endif


#ifdef IS_WINDOWS
    #define memmove(dst, src, size) memmove_s(dst, size, src, size)
#else
    #include<string.h>
#endif

#define strlen32(x) (uint32_t)strlen(x)

#define RUN_TEST(result) PRINTL("RUNNING TEST: " #result)  \
    if (result != 0) { return 1; }                         \
    else { PRINTL("\nPASSED: " #result) }                  \

#define TEST_GROUP(result) PRINTL("BEGINING GROUP: " #result)   \
    if (result != 0) { return 1; }                              \
    else { PRINTL("GROUP: "#result" COMPLETE")  }                \

/*Pre-computed constants for argument errors */
#define ARG_ERROR_POS_0 E_NULL_PTR
#define ARG_ERROR(pos) NCResultWithArgPosition(E_NULL_PTR, pos) 
#define ARG_ERROR_POS_1 ARG_ERROR(0x01)
#define ARG_ERROR_POS_2 ARG_ERROR(0x02)
#define ARG_ERROR_POS_3 ARG_ERROR(0x03)
#define ARG_ERROR_POS_4 ARG_ERROR(0x04)
#define ARG_ERROR_POS_5 ARG_ERROR(0x05)
#define ARG_ERROR_POS_6 ARG_ERROR(0x06)

#define ARG_RANGE_ERROR_POS_0 E_ARGUMENT_OUT_OF_RANGE
#define ARG_RANGE_ERROR(pos) NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, pos)
#define ARG_RANGE_ERROR_POS_1 ARG_RANGE_ERROR(0x01)
#define ARG_RANGE_ERROR_POS_2 ARG_RANGE_ERROR(0x02)
#define ARG_RANGE_ERROR_POS_3 ARG_RANGE_ERROR(0x03)
#define ARG_RANGE_ERROR_POS_4 ARG_RANGE_ERROR(0x04)
#define ARG_RANGE_ERROR_POS_5 ARG_RANGE_ERROR(0x05)
#define ARG_RANGE_ERROR_POS_6 ARG_RANGE_ERROR(0x06)

#define ARG_INVALID_ERROR_POS_0 E_INVALID_ARG
#define ARG_INVALID_ERROR(pos) NCResultWithArgPosition(E_INVALID_ARG, pos)
#define ARG_INVALID_ERROR_POS_1 ARG_INVALID_ERROR(0x01)
#define ARG_INVALID_ERROR_POS_2 ARG_INVALID_ERROR(0x02)
#define ARG_INVALID_ERROR_POS_3 ARG_INVALID_ERROR(0x03)
#define ARG_INVALID_ERROR_POS_4 ARG_INVALID_ERROR(0x04)
#define ARG_INVALID_ERROR_POS_5 ARG_INVALID_ERROR(0x05)
#define ARG_INVALID_ERROR_POS_6 ARG_INVALID_ERROR(0x06)

#ifndef TEST_BASE
    extern const NCContext* TestContext;
#endif

void FillRandomData(void* pbBuffer, size_t length);
