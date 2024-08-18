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
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using static VNLib.Utils.Cryptography.Noscrypt.NoscryptLibrary;

using NCResult = System.Int64;

namespace VNLib.Utils.Cryptography.Noscrypt
{

    public static class NCUtil
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

        internal static void CheckResult<T>(NCResult result, bool raiseOnFailure) where T : Delegate
        {
            //Only negative values are errors
            if (result >= NC_SUCCESS)
            {
                return;
            }

            NCResult asPositive = -result;

            // Error code are only 8 bits, if an argument error occured, the
            // argument number will be in the next upper 8 bits
            NCErrorCodes errorCode = (NCErrorCodes)(asPositive & 0xFF);
            byte argNumber = (byte)((asPositive >> 8) & 0xFF);

            switch (errorCode)
            {
                case NCErrorCodes.E_NULL_PTR:
                    RaiseNullArgExceptionForArgumentNumber<T>(argNumber);
                    break;
                case NCErrorCodes.E_INVALID_ARG:
                    RaiseArgExceptionForArgumentNumber<T>(argNumber);
                    break;
                case NCErrorCodes.E_ARGUMENT_OUT_OF_RANGE:
                    RaiseOORExceptionForArgumentNumber<T>(argNumber);
                    break;
                case NCErrorCodes.E_INVALID_CTX:
                    throw new InvalidOperationException("The library context object is null or invalid");
                case NCErrorCodes.E_OPERATION_FAILED:
                    RaiseOperationFailedException(raiseOnFailure);
                    break;
                case NCErrorCodes.E_VERSION_NOT_SUPPORTED:
                    throw new NotSupportedException("The requested version is not supported");

                default:
                    if(raiseOnFailure)
                    {
                        throw new InvalidOperationException($"The operation failed with error, code: {errorCode} for arugment {argNumber:x}");
                    }
                    break;
            }
        }

        private static void RaiseOperationFailedException(bool raise)
        {
            if (raise)
            {
                throw new InvalidOperationException("The operation failed for an unknown reason");
            }
        }

        private static void RaiseNullArgExceptionForArgumentNumber<T>(int argNumber) where T : Delegate
        {
            //Get delegate parameters
            Type type = typeof(T);
            ParameterInfo arg = type.GetMethod("Invoke")!.GetParameters()[argNumber];
            throw new ArgumentNullException(arg.Name, "Argument is null or invalid cannot continue");
        }

        private static void RaiseArgExceptionForArgumentNumber<T>(int argNumber) where T : Delegate
        {
            //Get delegate parameters
            Type type = typeof(T);
            ParameterInfo arg = type.GetMethod("Invoke")!.GetParameters()[argNumber];
            throw new ArgumentException("Argument is null or invalid cannot continue", arg.Name);
        }

        private static void RaiseOORExceptionForArgumentNumber<T>(int argNumber) where T : Delegate
        {
            //Get delegate parameters
            Type type = typeof(T);
            ParameterInfo arg = type.GetMethod("Invoke")!.GetParameters()[argNumber];
            throw new ArgumentOutOfRangeException(arg.Name, "Argument is out of range of acceptable values");
        }
    }
}
