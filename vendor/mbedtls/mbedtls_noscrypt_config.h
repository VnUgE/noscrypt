/*
 * Copyright (c) Vaughn Nugent
 *
 * This file is part of noscrypt, which is part of the VNLib collection
 * of libraries and utilities.
 *
 * noscrypt is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 2 of the License,
 * or (at your option) any later version.
 *
 * noscrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with noscrypt. If not, see http://www.gnu.org/licenses/.
 */

/*
 * Minimal mbed TLS configuration for noscrypt
 *
 * Only enables the modules noscrypt requires:
 * - SHA-256, HMAC, and HKDF for key derivation
 * - ChaCha20 for the ChaCha20 stream cipher
 */

/* System support */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME

/* mbed TLS modules */
#define MBEDTLS_MD_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_SHA256_C