
/*
* Copyright (c) 2026 Vaughn Nugent
*
* Package: noscrypt
* File: debug.h
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

#pragma once

#ifndef _NC_DEBUG_H
#define _NC_DEBUG_H

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

#endif /* !_NC_DEBUG_H */