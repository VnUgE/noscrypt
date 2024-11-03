﻿// Copyright (C) 2024 Vaughn Nugent
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

using VNLib.Utils.Cryptography.Noscrypt.@internal;

using static VNLib.Utils.Cryptography.Noscrypt.NoscryptLibrary;

using NCResult = System.Int64;

namespace VNLib.Utils.Cryptography.Noscrypt.Encryption
{
    public unsafe static class NCCipherUtil
    {
        /*
         * This class wraps the low-level cipher functions provided by 
         * the Noscrypt utility side-car library. 
         */

        internal static nint Alloc(NCContext ctx, uint version, uint flags)
        {
            nint cipher = GetTable(ctx).NCUtilCipherAlloc(version, flags);

            if (cipher == nint.Zero)
            {
                throw new OutOfMemoryException("Failed to allocate cipher context");
            }

            //Ensure flags are identical to those set during allocation
            Debug.Assert(GetFlags(ctx, cipher) == flags);

            return cipher;
        }

        internal static uint GetFlags(NCContext ctx, nint cipher)
        {
            NCResult result = GetTable(ctx).NCUtilCipherGetFlags(cipher);

            NCUtil.CheckResult<FunctionTable.NCUtilCipherGetFlagsDelegate>(result, raiseOnFailure: true);

            return (uint)result;
        }

        internal static void Free(NCContext ctx, nint cipher) => GetTable(ctx).NCUtilCipherFree(cipher);

        internal static int GetIvSize(NCContext ctx, nint cipher)
        {
            NCResult result = GetTable(ctx).NCUtilCipherGetIvSize(cipher);

            NCUtil.CheckResult<FunctionTable.NCUtilCipherGetIvSizeDelegate>(result, raiseOnFailure: true);

            return checked((int)result);
        }

        internal static void SetProperty(NCContext ctx, nint cipher, uint property, ref readonly byte value, uint valueLen)
        {
            fixed (byte* valPtr = &value)
            {
                NCResult result = GetTable(ctx).NCUtilCipherSetProperty(cipher, property, valPtr, valueLen);

                NCUtil.CheckResult<FunctionTable.NCUtilCipherSetPropertyDelegate>(result, raiseOnFailure: true);
            }
        }

        internal static uint GetOutputSize(NCContext ctx, nint cipher)
        {
            NCResult result = GetTable(ctx).NCUtilCipherGetOutputSize(cipher);

            NCUtil.CheckResult<FunctionTable.NCUtilCipherGetOutputSizeDelegate>(result, raiseOnFailure: true);

            return (uint)result;
        }

        internal static uint ReadOutput(NCContext ctx, nint cipher, ref byte outputData, uint outLen)
        {
            fixed (byte* outPtr = &outputData)
            {
                NCResult result = GetTable(ctx).NCUtilCipherReadOutput(cipher, outPtr, outLen);

                NCUtil.CheckResult<FunctionTable.NCUtilCipherReadOutputDelegate>(result, raiseOnFailure: true);

                return (uint)result;
            }
        }

        internal static void InitCipher(NCContext ctx, nint cipher, byte* inputPtr, uint inputSize)
        {
            NCResult result = GetTable(ctx).NCUtilCipherInit(cipher, inputPtr, inputSize);

            NCUtil.CheckResult<FunctionTable.NCUtilCipherInitDelegate>(result, raiseOnFailure: true);
        }

        internal static void Update(
            NCContext ctx,
            nint cipher,
            ref readonly NCSecretKey localKey,
            ref readonly NCPublicKey remoteKey
        )
        {
            fixed (NCSecretKey* sk = &localKey)
            fixed (NCPublicKey* pk = &remoteKey)
            {
                NCResult result = GetTable(ctx).NCUtilCipherUpdate(
                    cipher: cipher,
                    libContext: ctx.DangerousGetHandle(),
                    secKey: sk,
                    pubKey: pk
                );

                NCUtil.CheckResult<FunctionTable.NCUtilCipherInitDelegate>(result, raiseOnFailure: true);
            }
        }


#if DEBUG
        /*
         * Conversation key is not meant to be a public api. Callers 
         * should use Encrypt/Decrypt methods to handle encryption.
         * 
         * This method exists for vector testing purposes only.
         */
        public static void GetConverstationKey(
            NCContext ctx,
            ref readonly NCSecretKey localKey,
            ref readonly NCPublicKey remoteKey,
            Span<byte> conversationKeyOut32
        )
        {
            ArgumentNullException.ThrowIfNull(ctx);
            ArgumentOutOfRangeException.ThrowIfNotEqual(
                conversationKeyOut32.Length, 
                NC_CONVERSATION_KEY_SIZE, 
                nameof(conversationKeyOut32)
            );

            fixed (NCSecretKey* sk = &localKey)
            fixed (NCPublicKey* pk = &remoteKey)
            fixed(byte* convKey32Ptr = &MemoryMarshal.GetReference(conversationKeyOut32))
            {
                NCResult result = GetTable(ctx).NCGetConversationKey(
                    ctx: ctx.DangerousGetHandle(),
                    sk,
                    pk,
                    convKey32Ptr
                );

                NCUtil.CheckResult<FunctionTable.NCUtilCipherInitDelegate>(result, raiseOnFailure: true);
            }
        }
#endif

        private static ref readonly FunctionTable GetTable(NCContext ctx) 
            => ref ctx.Library.Functions;
    }

}