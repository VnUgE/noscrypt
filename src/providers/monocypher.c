/*
* Copyright (c) 2025 Vaughn Nugent
*
* Package: noscrypt
* File: providers/monocypher.c
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
*  This file handles some fallbacks that may not be available on 
*	some platforms. More specifically:
*		- Secure memset 0
* 		- Chacha20 cipher
* 
*/

#ifdef NC_ENABLE_MONOCYPHER

#include <monocypher/monocypher.h>

/* Export secure memse0 */
#ifndef _IMPL_SECURE_ZERO_MEMSET

	/* export cytpo wipe function as is */
	#define _IMPL_SECURE_ZERO_MEMSET crypto_wipe	
#endif

/* Export Chacha20 */
#ifndef _IMPL_CHACHA20_CRYPT

	#define _IMPL_CHACHA20_CRYPT _mc_chacha20_crypt

	_IMPLSTB cstatus_t _mc_chacha20_crypt(
		cspan_t key,
		cspan_t nonce,
		cspan_t input,
		span_t output
	)
	{
		/* Ensure output is large enough to store input data */
		if (ncSpanGetSize(output) < ncSpanGetSizeC(input))
		{
			return CSTATUS_FAIL;
		}

		/* 
		 * Guard conversion from 32bit int to size_t incase 
		 * incase the platform integer size is too small
		 */
#if SIZE_MAX < UINT32_MAX
		if (ncSpanGetSizeC(input) > SIZE_MAX)
		{
			return CSTATUS_FAIL;
		}
#endif

		/*
		* Function returns the next counter value which is not
		* needed for noscrypt as encryptions are one-shot, and 
		* require a new nonce for each encryption.
		* 
		* ITEF function uses a 12byte nonce and 32 byte key which 
		* is required for nip-44 compliant encryption. See monocypher.h
		*/

		DEBUG_ASSERT(ncSpanGetSizeC(key) == 0x20);
		DEBUG_ASSERT(ncSpanGetSizeC(nonce) == 0x0c);

		crypto_chacha20_ietf(
			ncSpanGetOffset(output, 0),
			ncSpanGetOffsetC(input, 0),
			ncSpanGetSizeC(input),
			ncSpanGetOffsetC(key, 0),
			ncSpanGetOffsetC(nonce, 0),
			0x00			/* Counter always starts at 0 */
		);

		return CSTATUS_OK;
	}

#endif

#endif /* !NC_ENABLE_MONOCYPHER */