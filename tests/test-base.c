/*
* Copyright (c) 2026 Vaughn Nugent
*
* Package: noscrypt
* File: test-base.c
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

#define TEST_BASE

#include "test.h"
#include "hex.h"

#ifdef IS_WINDOWS
    #include <bcrypt.h>
#endif

/*
* The test entry point, must be defined externally
*/
extern int RunTests(void);

/*
* The shared context for all tests. Defined extern in test.h
*/
NCContext* TestContext;

int main(void)
{
    uint8_t ctxRandom[32];

    PRINTL("Beginning test routines");

    FillRandomData(ctxRandom, 32);

    /*
    * Can use the shared/global context for tests that won't modify
    * the structure
    */
    TestContext = NCGetSharedContext();

    TASSERT(TestContext != NULL);

    TEST(NCInitContext(TestContext, ctxRandom), NC_SUCCESS);

    int result = RunTests();

    TEST(NCDestroyContext(TestContext), NC_SUCCESS);

    // Free any hex bytes allocated during tests to avoid memory leaks for valgrind etc
    FreeHexBytes();

    if (result == 0)
    {
        PRINTL("\nSUCCESS All tests passed");
    }

    return result;
}

void FillRandomData(void* pbBuffer, size_t length)
{

#ifdef IS_WINDOWS
    NTSTATUS status = BCryptGenRandom(NULL, pbBuffer, (ULONG)length, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    TASSERT(BCRYPT_SUCCESS(status));
#else
    FILE* f = fopen("/dev/urandom", "rb");
    TASSERT(f != NULL);
    TASSERT(fread(pbBuffer, 1, length, f) == length);
    fclose(f);
#endif
}

struct HexBytes {
    struct HexBytes* next;
    uint8_t* data;
    size_t size;
};

/* Deferred list of span_t to be freed on exit */
static struct HexBytes* _hexBytesHead;

static struct HexBytes* __allocHexBytes(size_t length)
{
    struct HexBytes* ptr;

    /* defend against invalid length */
    if (length == 0 || length % 2 != 0)
    {
        return NULL;
	}

    length /= 2;

    ptr = (struct HexBytes*)malloc(sizeof(struct HexBytes) + length);

    if (!ptr)
    {
        return NULL;
    }

    /* set data to point at the memory immediately following the HexBytes structure */
    ptr->data = (uint8_t*)(ptr + 1);
    ptr->size = length;

    return ptr;
}

span_t _fromHexString(const char* hexLiteral, uint32_t strLen)
{
    size_t i;
    span_t result;
    struct HexBytes* hexBytes;

    spanInit(&result, NULL, 0);

    if (!hexLiteral)
    {		
		return result;
    }

    /* alloc the raw bytes */
    hexBytes = __allocHexBytes(strLen);
    if (!hexBytes)
    {
		return result;
    }
    
    /* add to the defer linked list */
    hexBytes->next = _hexBytesHead;
    _hexBytesHead = hexBytes;

    /* read every 2 chars into  */
    for (i = 0; i < strLen; i += 2)
    {
        /* slice string into smaller 2 char strings then parse */
        char byteString[3] = { '\0' };

        byteString[0] = hexLiteral[i];
        byteString[1] = hexLiteral[i + 1];

        hexBytes->data[i / 2] = (uint8_t)strtol(byteString, NULL, 16);
    }

    spanInit(&result, hexBytes->data, (uint32_t)hexBytes->size);

    return result;
}

void FreeHexBytes(void)
{
    struct HexBytes* temp;

    while (_hexBytesHead)
    {
        temp = _hexBytesHead;
        _hexBytesHead = _hexBytesHead->next;
        free(temp);
    }
}

void PrintHexRaw(void* bytes, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
    {
        printf("%02x", ((uint8_t*)bytes)[i]);
    }

    puts("\n");
}

void PrintHexBytes(span_t hexBytes)
{
    if (!spanIsNull(hexBytes) && !spanIsEmpty(hexBytes))
    {
        PrintHexRaw(hexBytes.data, hexBytes.size);
    }
    else
    {
        puts("NULL");
    }
}