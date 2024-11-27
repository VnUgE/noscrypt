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
using static VNLib.Utils.Cryptography.Noscrypt.Noscrypt;

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
        /// <param name="key">A reference to the secret key instance</param>
        /// <returns>The secret key data span, or an empty span if a null reference is passed</returns>
        public static Span<byte> AsSpan(ref NCSecretKey key)
        {
            if (Unsafe.IsNullRef(in key))
            {
                return default;
            }

            //Safe to cast secret key to bytes, then we can make a span to its memory
            return MemoryMarshal.CreateSpan(
                ref Unsafe.As<NCSecretKey, byte>(ref key), 
                NCSecretKey.Size
            );
        }

        /// <summary>
        /// Gets a span of bytes from the current public key
        /// structure
        /// </summary>
        /// <param name="key"></param>
        /// <returns>The public key data as a data span, or an empty span if a null reference is passed</returns>
        public static Span<byte> AsSpan(ref NCPublicKey key)
        {
            if(Unsafe.IsNullRef(in key))
            {
                return default;
            }

            //Safe to cast secret key to bytes, then we can make a span to its memory
            return MemoryMarshal.CreateSpan(
                ref Unsafe.As<NCPublicKey, byte>(ref key),
                NCPublicKey.Size
            );
        }

        /// <summary>
        /// Gets a span of bytes from the current secret key 
        /// structure
        /// </summary>
        /// <param name="key">A readonly reference to the key structure</param>
        /// <returns>The secret key data span, or an empty span if a null reference is passed</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ReadOnlySpan<byte> AsReadonlySpan(ref readonly NCSecretKey key) 
            => AsSpan(ref Unsafe.AsRef(in key));

        /// <summary>
        /// Gets a span of bytes from the current public key
        /// structure
        /// </summary>
        /// <param name="key">A readonly reference to the key structure</param>
        /// <returns>The public key data as a data span, or an empty span if a null reference is passed</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Span<byte> AsReadonlySpan(ref readonly NCPublicKey key)
            => AsSpan(ref Unsafe.AsRef(in key));

        /// <summary>
        /// Casts a span of bytes to a secret key reference. Note that
        /// the new structure reference will point to the same memory
        /// as the span.
        /// </summary>
        /// <param name="span">The secret key data</param>
        /// <returns>A mutable secret key reference</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ref NCSecretKey AsSecretKey(Span<byte> span)
            => ref MemoryMarshal.AsRef<NCSecretKey>(span);

        /// <summary>
        /// Casts a span of bytes to a public key reference. Note that
        /// the new structure reference will point to the same memory
        /// as the span.
        /// </summary>
        /// <param name="span">The public key data span</param>
        /// <returns>A mutable reference to the public key structure</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ref NCPublicKey AsPublicKey(Span<byte> span) 
            => ref MemoryMarshal.AsRef<NCPublicKey>(span);

        /// <summary>
        /// Casts a read-only span of bytes to a secret key reference. Note that
        /// the new structure reference will point to the same memory as the span.
        /// </summary>
        /// <param name="span">The secret key data span</param>
        /// <returns>A readonly refernce to the secret key structure</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ref readonly NCSecretKey AsSecretKey(ReadOnlySpan<byte> span) 
            => ref MemoryMarshal.AsRef<NCSecretKey>(span);

        /// <summary>
        /// Casts a read-only span of bytes to a public key reference. Note that
        /// the new structure reference will point to the same memory as the span.
        /// </summary>
        /// <param name="span">The public key data span</param>
        /// <returns>A readonly reference to the public key structure</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ref readonly NCPublicKey AsPublicKey(ReadOnlySpan<byte> span) 
            => ref MemoryMarshal.AsRef<NCPublicKey>(span);

        /// <summary>
        /// Gets a nostr public key from a secret key.
        /// </summary>
        /// <param name="context">The noscrypt library context object</param>
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
        /// Gets a nostr public key from a secret key.
        /// </summary>
        /// <param name="context">The noscrypt library context object</param>
        /// <param name="secretKey">A buffer pointing to the initialized secret key</param>
        /// <param name="publicKey">A buffer pointing to memory to write the public key data to</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public static void GetPublicKey(NCContext context, ReadOnlySpan<byte> secretKey, Span<byte> publicKey)
        {
            GetPublicKey(
                context,
                in AsSecretKey(secretKey),
                ref AsPublicKey(publicKey)
            );
        }

        /// <summary>
        /// Validates a secret key is in a valid format. 
        /// </summary>
        /// <param name="secretKey">A readonly reference to key structure to validate</param>
        /// <returns>True if the key is consiered valid against the secp256k1 curve</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool ValidateSecretKey(NCContext context, ref readonly NCSecretKey secretKey)
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

        /// <summary>
        /// Validates a secret key is in a valid format. 
        /// </summary>
        /// <param name="context">The noscrypt library context object</param>
        /// <param name="secretKey">A readonly buffer to the secret structure. Must be at least <see cref="NCSecretKey.Size"/></param>
        /// <returns>True if the key is consiered valid against the secp256k1 curve</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool ValidateSecretKey(NCContext context, ReadOnlySpan<byte> secretKey) 
            => ValidateSecretKey(context, in AsSecretKey(secretKey));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Check(NCContext? context)
        {
            ArgumentNullException.ThrowIfNull(context);
            context.ThrowIfClosed();
        }

        private static ref readonly FunctionTable GetTable(NCContext ctx)
            => ref ctx.Library.Functions;
    }
}
