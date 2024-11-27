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

using VNLib.Utils.Extensions;
using VNLib.Utils.Cryptography.Noscrypt.@internal;
using static VNLib.Utils.Cryptography.Noscrypt.Noscrypt;

using NCResult = System.Int64;

namespace VNLib.Utils.Cryptography.Noscrypt.Singatures
{

    /// <summary>
    /// Contains utility methods for signing and verifying data using the noscrypt library
    /// </summary>
    public unsafe static class NCSignatureUtil
    {
        /// <summary>
        /// Signs the data using the supplied secret key and 
        /// entropy pointer
        /// </summary>
        /// <param name="context">The initialized context memory to pass to the library</param>
        /// <param name="secretKey">A reference to a structure containing the private key data</param>
        /// <param name="random32">A pointer to a 32 byte buffer containing high entropy random data</param>
        /// <param name="data">A pointer to a buffer containing the data to sign</param>
        /// <param name="dataSize">The size of the data buffer in bytes</param>
        /// <param name="sig64">A pointer to a 64 byte buffer to write signature data to</param>
        /// <exception cref="InvalidOperationException"></exception>
        public static void SignData(
            NCContext context,
            ref readonly NCSecretKey secretKey,
            ref readonly byte random32,
            ref readonly byte data,
            uint dataSize,
            ref byte sig64
        )
        {
            Check(context);

            fixed (NCSecretKey* pSecKey = &secretKey)
            fixed (byte* pData = &data, pSig = &sig64, pRandom = &random32)
            {
                NCResult result = GetTable(context).NCSignData(
                    ctx: context.DangerousGetHandle(),
                    sk: pSecKey,
                    random32: pRandom,
                    data: pData,
                    dataSize,
                    sig64: pSig
                );

                NCUtil.CheckResult<FunctionTable.NCSignDataDelegate>(result, raiseOnFailure: true);
            }
        }

        /// <summary>
        /// Verifies signed data against the supplied public key
        /// </summary>
        /// <param name="context">The initialized context memory to pass to the library</param>
        /// <param name="publicKey">A reference to a structure containing the public key data</param>
        /// <param name="data">A pointer to a buffer containing the data to verify</param>
        /// <param name="dataSize">The size of the data buffer in bytes</param>
        /// <param name="sig64">A pointer to a 64 byte buffer to read signature data from</param>
        /// <returns>True if the signature was signed by the supplied public key, false otherwise</returns>
        public static bool VerifyData(
            NCContext context,
            ref readonly NCPublicKey publicKey,
            ref readonly byte data,
            uint dataSize,
            ref readonly byte sig64
        )
        {
            Check(context);

            fixed (NCPublicKey* pPubKey = &publicKey)
            fixed (byte* pData = &data, pSig = &sig64)
            {
                NCResult result = GetTable(context).NCVerifyData(
                    context.DangerousGetHandle(),
                    pk: pPubKey,
                    data: pData,
                    dataSize,
                    sig64: pSig
                );

                NCUtil.CheckResult<FunctionTable.NCVerifyDataDelegate>(result, false);

                return result == NC_SUCCESS;
            }
        }

        /// <summary>
        /// Signs the data using the supplied secret key and 
        /// entropy pointer
        /// </summary>
        /// <param name="context">The initialized context memory to pass to the library</param>
        /// <param name="secretKey">A reference to a structure containing the private key data</param>
        /// <param name="random32">A pointer to a 32 byte buffer containing high entropy random data</param>
        /// <param name="data">A pointer to a buffer containing the data to sign</param>
        /// <param name="signatureBuffer">A pointer to a 64 byte buffer to write signature data to</param>
        /// <exception cref="InvalidOperationException"></exception>
        public static void SignData(
            NCContext context,
            ref readonly NCSecretKey secretKey,
            ReadOnlySpan<byte> random32,
            ReadOnlySpan<byte> data,
            Span<byte> signatureBuffer
        )
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(signatureBuffer.Length, NC_SIGNATURE_SIZE, nameof(signatureBuffer));
            ArgumentOutOfRangeException.ThrowIfLessThan(random32.Length, 32, nameof(random32));
            ArgumentOutOfRangeException.ThrowIfZero(data.Length, nameof(data));

            SignData(
                context,
                secretKey: in secretKey,
                random32: in MemoryMarshal.GetReference(random32),
                data: in MemoryMarshal.GetReference(data),
                dataSize: (uint)data.Length,
                sig64: ref MemoryMarshal.GetReference(signatureBuffer)
            );
        }

        /// <summary>
        /// Verifies signed data against the supplied public key
        /// </summary>
        /// <param name="context">The initialized context memory to pass to the library</param>
        /// <param name="publicKey">A reference to a structure containing the public key data</param>
        /// <param name="data">A pointer to a buffer containing the data to verify</param>
        /// <param name="signatureBuffer">A pointer to a 64 byte buffer to read signature data from</param>
        /// <returns>True if the signature was signed by the supplied public key, false otherwise</returns>
        public static bool VerifyData(
            NCContext context,
            ref readonly NCPublicKey publicKey,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> signatureBuffer
        )
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(signatureBuffer.Length, NC_SIGNATURE_SIZE, nameof(signatureBuffer));
            ArgumentOutOfRangeException.ThrowIfZero(data.Length, nameof(data));

            return VerifyData(
                context,
                publicKey: in publicKey,
                data: in MemoryMarshal.GetReference(data),
                dataSize: (uint)data.Length,
                sig64: ref MemoryMarshal.GetReference(signatureBuffer)
            );
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
