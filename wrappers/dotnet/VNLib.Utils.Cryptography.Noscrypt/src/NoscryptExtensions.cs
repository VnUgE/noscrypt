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
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using static VNLib.Utils.Cryptography.Noscrypt.NoscryptLibrary;

namespace VNLib.Utils.Cryptography.Noscrypt
{

    public static class NoscryptExtensions
    {
        public static void SignData(
            this INostrCrypto lib,
            ref readonly NCSecretKey secKey,
            ReadOnlySpan<byte> random32,
            ReadOnlySpan<byte> data,
            Span<byte> signatureBuffer
        )
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(signatureBuffer.Length, NC_SIGNATURE_SIZE, nameof(signatureBuffer));
            ArgumentOutOfRangeException.ThrowIfLessThan(random32.Length, 32, nameof(random32));
            ArgumentOutOfRangeException.ThrowIfZero(data.Length, nameof(data));

            lib.SignData(
                secretKey: in secKey,
                random32: in MemoryMarshal.GetReference(random32),
                data: in MemoryMarshal.GetReference(data),
                dataSize: (uint)data.Length,
                sig64: ref MemoryMarshal.GetReference(signatureBuffer)
            );
        }

#if DEBUG
        /*
         * Conversation key is not meant to be a public api. Callers 
         * should use Encrypt/Decrypt methods to handle encryption.
         * 
         * This method exists for vector testing purposes only.
         */
        public static void GetConverstationKey(
            this NostrCrypto lib,
            ref readonly NCSecretKey secretKey,
            ref readonly NCPublicKey publicKey,
            Span<byte> conversationKeyOut32
        )
        {
            ArgumentNullException.ThrowIfNull(lib);
            ArgumentOutOfRangeException.ThrowIfNotEqual(conversationKeyOut32.Length, NC_CONVERSATION_KEY_SIZE, nameof(conversationKeyOut32));

            //Get the conversation key
            lib.GetConverstationKey(
                secretKey: in secretKey,
                publicKey: in publicKey,
                key32: ref MemoryMarshal.GetReference(conversationKeyOut32)
            );

        }
#endif
    }
}
