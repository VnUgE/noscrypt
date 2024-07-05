/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: noscryptutil.h
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
* noscrypt is a an open-source, strict C89 library that performs the basic
* cryptographic operations found in the Nostr protocol. It is designed to be
* portable and easy to use in any C89 compatible environment. It is also designed
*/

#pragma once

#ifndef NOSCRYPTUTIL_H
#define NOSCRYPTUTIL_H

#ifdef __cplusplus
extern "C" {
#endif 

#include <stdlib.h>
#include "noscrypt.h"

#define E_OUT_OF_MEMORY		-10

typedef struct nc_util_enc_struct NCUtilEncryptionContext;

NC_EXPORT NCResult NC_CC NCUtilGetEncryptionPaddedSize(uint32_t encVersion, int32_t plaintextSize);

NC_EXPORT NCResult NC_CC NCUtilGetEncryptionBufferSize(uint32_t encVersion, int32_t plaintextSize);

NC_EXPORT NCUtilEncryptionContext* NC_CC NCUtilAllocEncryptionContext(uint32_t encVersion);

NC_EXPORT NCResult NC_CC NCUtilInitEncryptionContext(
	NCUtilEncryptionContext* encCtx,
	const uint8_t* plainText,
	uint32_t plainTextSize
);

NC_EXPORT void NC_CC NCUtilFreeEncryptionContext(NCUtilEncryptionContext* encCtx);

NC_EXPORT NCResult NC_CC NCUtilGetEncryptedSize(const NCUtilEncryptionContext* encCtx);

NC_EXPORT NCResult NC_CC NCUtilReadEncryptedData(
	const NCUtilEncryptionContext* encCtx,
	uint8_t* output,
	uint32_t outputSize
);

NC_EXPORT NCResult NCUtilSetEncryptionProperty(
	NCUtilEncryptionContext* ctx,
	uint32_t property,
	uint8_t* value,
	uint32_t valueLen
);

#ifdef __cplusplus
}
#endif

#endif /* NOSCRYPTUTIL_H */