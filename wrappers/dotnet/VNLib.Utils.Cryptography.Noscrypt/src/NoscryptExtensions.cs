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
        public static void EncryptNip44(
            this INostrCrypto lib,
            ref readonly NCSecretKey secretKey,
            ref readonly NCPublicKey publicKey,
            ReadOnlySpan<byte> nonce32,
            ReadOnlySpan<byte> plainText,
            Span<byte> hmackKeyOut32,
            Span<byte> cipherText
        )
        {
            ArgumentNullException.ThrowIfNull(lib);

            //Chacha requires the output buffer to be at-least the size of the input buffer
            ArgumentOutOfRangeException.ThrowIfGreaterThan(plainText.Length, cipherText.Length, nameof(plainText));

            //Nonce must be exactly 32 bytes
            ArgumentOutOfRangeException.ThrowIfNotEqual(nonce32.Length, NC_ENCRYPTION_NONCE_SIZE, nameof(nonce32));

            ArgumentOutOfRangeException.ThrowIfNotEqual(hmackKeyOut32.Length, NC_HMAC_KEY_SIZE, nameof(hmackKeyOut32));

            //Encrypt data, use the plaintext buffer size as the data size
            lib.EncryptNip44(
                secretKey: in secretKey,
                publicKey: in publicKey,
                nonce32: in MemoryMarshal.GetReference(nonce32),
                plainText: in MemoryMarshal.GetReference(plainText),
                cipherText: ref MemoryMarshal.GetReference(cipherText),
                size: (uint)plainText.Length,
                hmacKeyOut32: ref MemoryMarshal.GetReference(hmackKeyOut32)
            );
        }

        public static unsafe void EncryptNip44(
            this INostrCrypto lib,
            ref NCSecretKey secretKey,
            ref NCPublicKey publicKey,
            void* nonce32,
            void* hmacKeyOut32,
            void* plainText,
            void* cipherText,
            uint size
        )
        {
            ArgumentNullException.ThrowIfNull(plainText);
            ArgumentNullException.ThrowIfNull(cipherText);
            ArgumentNullException.ThrowIfNull(nonce32);

            //Spans are easer to forward references from pointers without screwing up arguments
            lib.EncryptNip44(
                secretKey: in secretKey,
                publicKey: in publicKey,
                nonce32: in Unsafe.AsRef<byte>(nonce32),
                plainText: in Unsafe.AsRef<byte>(plainText),               
                cipherText: ref Unsafe.AsRef<byte>(cipherText),
                size: size,
                hmacKeyOut32: ref Unsafe.AsRef<byte>(hmacKeyOut32)
            );
        }


        public static void DecryptNip44(
            this INostrCrypto lib,
            ref readonly NCSecretKey secretKey,
            ref readonly NCPublicKey publicKey,
            ReadOnlySpan<byte> nonce32,
            ReadOnlySpan<byte> cipherText,
            Span<byte> plainText
        )
        {
            ArgumentNullException.ThrowIfNull(lib);

            //Chacha requires the output buffer to be at-least the size of the input buffer
            ArgumentOutOfRangeException.ThrowIfGreaterThan(cipherText.Length, plainText.Length, nameof(cipherText));

            //Nonce must be exactly 32 bytes
            ArgumentOutOfRangeException.ThrowIfNotEqual(nonce32.Length, 32, nameof(nonce32));

            //Decrypt data, use the ciphertext buffer size as the data size
            lib.DecryptNip44(
                secretKey: in secretKey,
                publicKey: in publicKey,
                nonce32: in MemoryMarshal.GetReference(nonce32),
                cipherText: in MemoryMarshal.GetReference(cipherText),
                plainText: ref MemoryMarshal.GetReference(plainText),
                size: (uint)cipherText.Length
            );
        }

        public static unsafe void DecryptNip44(
            this INostrCrypto lib,
            ref readonly NCSecretKey secretKey,
            ref readonly NCPublicKey publicKey,
            void* nonce32,
            void* cipherText,
            void* plainText,
            uint size
        )
        {
            ArgumentNullException.ThrowIfNull(nonce32);
            ArgumentNullException.ThrowIfNull(cipherText);
            ArgumentNullException.ThrowIfNull(plainText);

            //Spans are easer to forward references from pointers without screwing up arguments
            DecryptNip44(
                lib: lib,
                secretKey: in secretKey,
                publicKey: in publicKey,
                nonce32: new Span<byte>(nonce32, NC_ENCRYPTION_NONCE_SIZE),
                cipherText: new Span<byte>(cipherText, (int)size),
                plainText: new Span<byte>(plainText, (int)size)
            );
        }

        public static bool VerifyMac(
            this INostrCrypto lib,
            ref readonly NCSecretKey secretKey,
            ref readonly NCPublicKey publicKey,
            ReadOnlySpan<byte> nonce32,
            ReadOnlySpan<byte> mac32,
            ReadOnlySpan<byte> payload
        )
        {
            ArgumentNullException.ThrowIfNull(lib);
            ArgumentOutOfRangeException.ThrowIfZero(payload.Length, nameof(payload));
            ArgumentOutOfRangeException.ThrowIfNotEqual(nonce32.Length, NC_ENCRYPTION_NONCE_SIZE, nameof(nonce32));
            ArgumentOutOfRangeException.ThrowIfNotEqual(mac32.Length, NC_ENCRYPTION_MAC_SIZE, nameof(mac32));

            //Verify the HMAC
            return lib.VerifyMac(
                secretKey: in secretKey,
                publicKey: in publicKey,
                nonce32: in MemoryMarshal.GetReference(nonce32),
                mac32: in MemoryMarshal.GetReference(mac32),
                payload: in MemoryMarshal.GetReference(payload),
                payloadSize: (uint)payload.Length
            );
        }

        public static unsafe bool VerifyMac(
            this INostrCrypto lib,
            ref readonly NCSecretKey secretKey,
            ref readonly NCPublicKey publicKey,
            void* nonce32,
            void* mac32,
            void* payload,
            uint payloadSize
        )
        {
            ArgumentNullException.ThrowIfNull(nonce32);
            ArgumentNullException.ThrowIfNull(mac32);
            ArgumentNullException.ThrowIfNull(payload);

            return lib.VerifyMac(
                secretKey: in secretKey,
                publicKey: in publicKey,
                nonce32: in Unsafe.AsRef<byte>(nonce32),
                mac32: in Unsafe.AsRef<byte>(mac32),
                payload: in Unsafe.AsRef<byte>(payload),
                payloadSize: payloadSize
            );
        }

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
