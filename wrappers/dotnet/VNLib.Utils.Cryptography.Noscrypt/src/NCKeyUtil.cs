// Copyright (C) 2024 Vaughn Nugent
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

using System;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

using VNLib.Utils.Extensions;
using VNLib.Utils.Cryptography.Noscrypt.@internal;
using static VNLib.Utils.Cryptography.Noscrypt.NoscryptLibrary;

using NCResult = System.Int64;

namespace VNLib.Utils.Cryptography.Noscrypt
{
    /// <summary>
    /// Contains utility methods for working with nostr keys
    /// </summary>
    public static unsafe class NCKeyUtil
    {
        /// <summary>
        /// Gets a span of bytes from the current secret key 
        /// structure
        /// </summary>
        /// <param name="key"></param>
        /// <returns>The secret key data span</returns>
        public unsafe static Span<byte> AsSpan(this ref NCSecretKey key)
        {
            //Safe to cast secret key to bytes, then we can make a span to its memory
            ref byte asBytes = ref Unsafe.As<NCSecretKey, byte>(ref key);
            return MemoryMarshal.CreateSpan(ref asBytes, sizeof(NCSecretKey));
        }

        /// <summary>
        /// Gets a span of bytes from the current public key
        /// structure
        /// </summary>
        /// <param name="key"></param>
        /// <returns>The public key data as a data span</returns>
        public unsafe static Span<byte> AsSpan(this ref NCPublicKey key)
        {
            //Safe to cast secret key to bytes, then we can make a span to its memory
            ref byte asBytes = ref Unsafe.As<NCPublicKey, byte>(ref key);
            return MemoryMarshal.CreateSpan(ref asBytes, sizeof(NCPublicKey));
        }

        /// <summary>
        /// Casts a span of bytes to a secret key reference. Note that
        /// the new structure reference will point to the same memory
        /// as the span.
        /// </summary>
        /// <param name="span">The secret key data</param>
        /// <returns>A mutable secret key reference</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe static ref NCSecretKey AsSecretKey(Span<byte> span)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(span.Length, sizeof(NCSecretKey), nameof(span));

            ref byte asBytes = ref MemoryMarshal.GetReference(span);
            return ref Unsafe.As<byte, NCSecretKey>(ref asBytes);
        }

        /// <summary>
        /// Casts a span of bytes to a public key reference. Note that
        /// the new structure reference will point to the same memory
        /// as the span.
        /// </summary>
        /// <param name="span">The public key data span</param>
        /// <returns>A mutable reference to the public key structure</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe static ref NCPublicKey AsPublicKey(Span<byte> span)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(span.Length, sizeof(NCPublicKey), nameof(span));

            ref byte asBytes = ref MemoryMarshal.GetReference(span);
            return ref Unsafe.As<byte, NCPublicKey>(ref asBytes);
        }

        /// <summary>
        /// Casts a read-only span of bytes to a secret key reference. Note that
        /// the new structure reference will point to the same memory as the span.
        /// </summary>
        /// <param name="span">The secret key data span</param>
        /// <returns>A readonly refernce to the secret key structure</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe static ref readonly NCSecretKey AsSecretKey(ReadOnlySpan<byte> span)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(span.Length, sizeof(NCSecretKey), nameof(span));

            ref byte asBytes = ref MemoryMarshal.GetReference(span);
            return ref Unsafe.As<byte, NCSecretKey>(ref asBytes);
        }

        /// <summary>
        /// Casts a read-only span of bytes to a public key reference. Note that
        /// the new structure reference will point to the same memory as the span.
        /// </summary>
        /// <param name="span">The public key data span</param>
        /// <returns>A readonly reference to the public key structure</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public unsafe static ref readonly NCPublicKey AsPublicKey(ReadOnlySpan<byte> span)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(span.Length, sizeof(NCPublicKey), nameof(span));

            ref byte asBytes = ref MemoryMarshal.GetReference(span);
            return ref Unsafe.As<byte, NCPublicKey>(ref asBytes);
        }

        /// <summary>
        /// Gets a nostr public key from a secret key.
        /// </summary>
        /// <param name="secretKey">A reference to the secret key to get the public key from</param>
        /// <param name="publicKey">A reference to the public key structure to write the recovered key to</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public static void GetPublicKey(
            NCContext context,
            ref readonly NCSecretKey secretKey,
            ref NCPublicKey publicKey
        )
        {
            Check(context);

            fixed (NCSecretKey* pSecKey = &secretKey)
            fixed (NCPublicKey* pPubKey = &publicKey)
            {
                NCResult result = GetTable(context).NCGetPublicKey(
                    context.DangerousGetHandle(),
                    pSecKey,
                    pPubKey
                );

                NCUtil.CheckResult<FunctionTable.NCGetPublicKeyDelegate>(result, raiseOnFailure: true);
            }
        }

        /// <summary>
        /// Validates a secret key is in a valid format. 
        /// </summary>
        /// <param name="secretKey">A readonly reference to key structure to validate</param>
        /// <returns>True if the key is consiered valid against the secp256k1 curve</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool ValidateSecretKey(
            NCContext context,
            ref readonly NCSecretKey secretKey
        )
        {
            Check(context);

            fixed (NCSecretKey* pSecKey = &secretKey)
            {
                NCResult result = GetTable(context).NCValidateSecretKey(
                    context.DangerousGetHandle(),
                    pSecKey
                );

                NCUtil.CheckResult<FunctionTable.NCValidateSecretKeyDelegate>(result, raiseOnFailure: false);

                return result == NC_SUCCESS;
            }
        }

        private static void Check(NCContext? context)
        {
            ArgumentNullException.ThrowIfNull(context);
            context.ThrowIfClosed();
        }

        private static ref readonly FunctionTable GetTable(NCContext ctx)
            => ref ctx.Library.Functions;
    }
}
