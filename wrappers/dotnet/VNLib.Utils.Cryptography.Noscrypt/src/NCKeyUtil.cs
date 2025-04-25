// Copyright (C) 2025 Vaughn Nugent
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
using System.Diagnostics;
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
    public static class NCKeyUtil
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
        public static unsafe void GetPublicKey(
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
        public static unsafe bool ValidateSecretKey(NCContext context, ref readonly NCSecretKey secretKey)
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

        /// <summary>
        /// Converts a hexadecimal encoded secret key to a secret key structure
        /// </summary>
        /// <param name="hexSecKey">The 32 byte hexadecimal encoded secret key</param>
        /// <param name="secretKey">A pointer to the secret key structure to write the key data to</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public static void FromHex(string hexSecKey, ref NCSecretKey secretKey)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(hexSecKey);

            FromHex(hexSecKey.AsSpan(), ref secretKey);
        }

        /// <summary>
        /// Converts a hexadecimal encoded public key to a public key structure
        /// </summary>
        /// <param name="hexPubKey">The 32 byte hexadecimal encoded public key</param>
        /// <param name="publicKey">A pointer to the public key structure to write the key data to</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public static void FromHex(string hexPubKey, ref NCPublicKey publicKey)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(hexPubKey);

            FromHex(hexPubKey.AsSpan(), ref publicKey);
        }

        /// <summary>
        /// Converts a hexadecimal encoded secret key to a secret key structure
        /// </summary>
        /// <param name="hexSecKey">The 32 byte hexadecimal encoded secret key</param>
        /// <param name="secretKey">A pointer to the secret key structure to write the key data to</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public static void FromHex(ReadOnlySpan<char> hexSecKey, ref NCSecretKey secretKey)
        {
            ArgumentOutOfRangeException.ThrowIfNotEqual(hexSecKey.Length, NCSecretKey.Size * 2, nameof(hexSecKey));

            FastDecodeHex(hexSecKey, AsSpan(ref secretKey));
        }

        /// <summary>
        /// Converts a hexadecimal encoded public key to a public key structure
        /// </summary>
        /// <param name="hexPubKey">The 32 byte hexadecimal encoded public key</param>
        /// <param name="publicKey">A pointer to the public key structure to write the key data to</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public static void FromHex(ReadOnlySpan<char> hexPubKey, ref NCPublicKey publicKey)
        {
            ArgumentOutOfRangeException.ThrowIfNotEqual(hexPubKey.Length, NCPublicKey.Size * 2, nameof(hexPubKey));

            FastDecodeHex(hexPubKey, AsSpan(ref publicKey));
        }

        private static void FastDecodeHex(ReadOnlySpan<char> input, Span<byte> output)
        {
            for (int i = 0; i < input.Length; i += 2)
            {
                byte b1 = CharToByte(input[i]);
                byte b2 = CharToByte(input[i + 1]);
                output[i / 2] = (byte)((b1 << 4) | b2);
            }
        }

        private static byte CharToByte(char c)
        {
            if (c >= '0' && c <= '9')
            {
                return (byte)(c - '0');
            }
            
            if (c >= 'a' && c <= 'f')
            {
                return (byte)(c - 'a' + 10);
            }
            
            if (c >= 'A' && c <= 'F')
            {
                return (byte)(c - 'A' + 10);
            }

            throw new ArgumentException($"Input data contained invalid hexadecimal character data: '{c}'");
        }

        public static bool AreEqual(ref readonly NCPublicKey first, ref readonly NCPublicKey second)
        {
            return AreEqual<NCPublicKey>(in first, in second);
        }

        public static bool AreEqual(ref readonly NCSecretKey first, ref readonly NCSecretKey second)
        {
            return AreEqual<NCSecretKey>(in first, in second);
        }

        public static unsafe bool AreEqual<T>(ref readonly T first, ref readonly T second) where T : unmanaged
        {
            //Ensure the size of the structure is a multiple of long
            Debug.Assert(sizeof(T) % sizeof(long) == 0);

            //If pointers to the same memory, they are equal
            if (Unsafe.AreSame(in first, in second))
            {
                return true;
            }

            ref long f = ref Unsafe.As<T, long>(ref Unsafe.AsRef(in first));
            ref long s = ref Unsafe.As<T, long>(ref Unsafe.AsRef(in second));

            for (int i = 0; i < sizeof(T) / sizeof(long); i++)
            {
                if (Unsafe.Add(ref f, i) != Unsafe.Add(ref s, i))
                {
                    return false;
                }
            }

            return true;
        }

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
