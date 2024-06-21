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
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Authentication;

using VNLib.Utils.Extensions;
using VNLib.Utils.Memory;

using static VNLib.Utils.Cryptography.Noscrypt.NoscryptLibrary;

namespace VNLib.Utils.Cryptography.Noscrypt
{

    public sealed class NostrMessageCipher(INostrCrypto lib, INostrEncryptionVersion version) : VnDisposeable
    {
        const int Nip44MaxMessageSize = 65603;

        private readonly INostrCrypto library = lib;

        private NCSecretKey _fromKey;
        private NCPublicKey _toKey;       
        private Buffer32 _nonce32;
        private Buffer32 _mac32;

        /// <summary>
        /// The message encryption version used by this instance
        /// </summary>
        public uint Version { get; } = version.Version;

        /// <summary>
        /// The message nonce created during encryption event
        /// </summary>
        public unsafe Span<byte> Nonce => MemoryMarshal.CreateSpan(ref GetNonceRef(), sizeof(Buffer32));

        /// <summary>
        /// The message MAC set during encryption, and required for decryption
        /// </summary>
        public unsafe Span<byte> Mac => MemoryMarshal.CreateSpan(ref GetMacRef(), sizeof(Buffer32));

        /// <summary>
        /// Gets the size of the buffer required to encrypt the specified data size
        /// </summary>
        /// <param name="dataSize">The size of the message raw plaintext message to send</param>
        /// <returns>The minimum number of bytes required for message encryption output</returns>
        /// <exception cref="NotSupportedException"></exception>
        public int GetPayloadBufferSize(int dataSize) 
            => version.GetPayloadBufferSize(dataSize);

        /// <summary>
        /// Gets the size of the buffer required to hold the full encrypted message data
        /// for the encryption version used
        /// </summary>
        /// <param name="dataSize">The plaintext data size</param>
        /// <returns>The estimated size of the output buffer</returns>
        public int GetMessageBufferSize(int dataSize)
            => version.GetMessageBufferSize(dataSize);

        /// <summary>
        /// Sets the encryption secret key for the message
        /// </summary>
        /// <param name="secKey">The secret key buffer</param>
        /// <returns>The current instance for chaining</returns>
        /// <exception cref="ArgumentException"></exception>
        public NostrMessageCipher SetSecretKey(ReadOnlySpan<byte> secKey) 
            => SetSecretKey(in NCUtil.AsSecretKey(secKey));

        /// <summary>
        /// Sets the encryption secret key for the message
        /// </summary>
        /// <param name="secKey">The secret key structure to copy</param>
        /// <returns>The current instance for chaining</returns>
        /// <exception cref="ArgumentException"></exception>
        public NostrMessageCipher SetSecretKey(ref readonly NCSecretKey secKey)
        {
            MemoryUtil.CloneStruct(in secKey, ref _fromKey);
            return this;
        }

        /// <summary>
        /// Assigns the public key used to encrypt the message as the 
        /// receiver of the message
        /// </summary>
        /// <param name="pubKey">The user's public key receiving the message</param>
        /// <returns>The current instance for chaining</returns>
        /// <exception cref="ArgumentException"></exception>
        public NostrMessageCipher SetPublicKey(ReadOnlySpan<byte> pubKey) 
            => SetPublicKey(in NCUtil.AsPublicKey(pubKey));

        /// <summary>
        /// Assigns the public key used to encrypt the message as the 
        /// receiver of the message
        /// </summary>
        /// <param name="pubKey">The user's public key receiving the message</param>
        /// <returns>The current instance for chaining</returns>
        /// <exception cref="ArgumentException"></exception>
        public NostrMessageCipher SetPublicKey(ref readonly NCPublicKey pubKey)
        {
            MemoryUtil.CloneStruct(in pubKey, ref _toKey);
            return this;
        }

        /// <summary>
        /// Assigns the nonce to the message. Must be <see cref="NC_ENCRYPTION_NONCE_SIZE"/>
        /// in length
        /// </summary>
        /// <param name="nonce">The nonce value to copy</param>
        /// <returns>The current instance for chaining</returns>
        /// <exception cref="ArgumentException"></exception>
        public NostrMessageCipher SetNonce(ReadOnlySpan<byte> nonce)
        {
            MemoryUtil.CopyStruct(nonce, ref _nonce32);
            return this;
        }

        /// <summary>
        /// Assigns a random nonce using the specified random source
        /// </summary>
        /// <param name="rng">The random source to genrate a random nonce from</param>
        /// <returns>The current instance for chaining</returns>
        public NostrMessageCipher SetRandomNonce(IRandomSource rng)
        {
            rng.GetRandomBytes(Nonce);
            return this;
        }

        /// <summary>
        /// Configures a 32 byte mac for the message for nip44 decryption
        /// </summary>
        /// <param name="mac">The message mac</param>
        /// <returns>The current instance for chaining</returns>
        public NostrMessageCipher SetMac(ReadOnlySpan<byte> mac)
        {
            MemoryUtil.CopyStruct(mac, ref _mac32);
            return this;
        }

        /// <summary>
        /// Decrypts a full nostr encrypted message and writes the plaintext 
        /// data to the output buffer
        /// </summary>
        /// <param name="message">The nostr message buffer to decrypt</param>
        /// <param name="plaintext">The output plaintext buffer</param>
        /// <returns>The number of bytes written the the plaintext buffer</returns>
        /// <exception cref="FormatException"></exception>
        /// <exception cref="NotSupportedException"></exception>
        public int DecryptMessage(ReadOnlySpan<byte> message, Span<byte> plaintext)
        {
            return Version switch
            {
                NC_ENC_VERSION_NIP44 => DecryptNip44Message(message, plaintext),
                _ => throw new NotSupportedException("NIP04 encryption is not supported"),
            };
        }

        /// <summary>
        /// Encrypts the plaintext message and writes the encrypted message to the
        /// specified buffer. The output matches the format of the full nostr message
        /// for the specified encryption version
        /// </summary>
        /// <param name="plaintext">The plaintext data to be encrypted</param>
        /// <param name="message">The buffer to write the encrypted message data to</param>
        /// <returns>The number of bytes written to the message buffer</returns>
        /// <exception cref="NotSupportedException"></exception>
        public int EncryptMessage(ReadOnlySpan<byte> plaintext, Span<byte> message)
        {
            return Version switch
            {
                NC_ENC_VERSION_NIP44 => EncryptNip44Message(plaintext, message),
                _ => throw new NotSupportedException("NIP04 encryption is not supported"),
            };
        }

        private int EncryptNip44Message(ReadOnlySpan<byte> plaintext, Span<byte> message)
        {
            int minRequiredOutSize = Nip44Util.CalcFinalBufferSize(plaintext.Length);

            ArgumentOutOfRangeException.ThrowIfZero(plaintext.Length, nameof(plaintext));
            ArgumentOutOfRangeException.ThrowIfLessThan(message.Length, minRequiredOutSize, nameof(message));

            ForwardOnlyWriter<byte> messageWriter = new(message);

            // From spec -> concat(version, nonce, ciphertext, mac)
            messageWriter.Append(0x02);          // Version
            messageWriter.Append<byte>(Nonce);      // nonce

            //Encrypt plaintext and write directly the message buffer
            int written = EncryptPayload(plaintext, messageWriter.Remaining);

            messageWriter.Advance(written);

            //Append the message mac, it was writen after the encryption operation
            messageWriter.Append<byte>(Mac);

            return messageWriter.Written;
        }

        /// <summary>
        /// Encrypts the plaintext message and writes the encrypted message to the
        /// specified buffer, along with a 32 byte mac of the message
        /// </summary>
        /// <param name="plaintext">The plaintext data to encrypt</param>
        /// <param name="message">The message output buffer to write encrypted data to</param>
        /// <param name="macOut32">A buffer to write the computed message mac to</param>
        /// <returns>The number of bytes writtn to the message output buffer</returns>
        /// <remarks>
        /// The message buffer must be at-least the size of the output buffer, and it is not 
        /// initialized before the encryption operation.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public int EncryptPayload(ReadOnlySpan<byte> plaintext, Span<byte> message)
        {
            return Version switch
            {
                NC_ENC_VERSION_NIP44 => EncryptNip44(plaintext, message),
                _ => throw new NotSupportedException("NIP04 encryption is not supported"),
            };
        }

        private int EncryptNip44(ReadOnlySpan<byte> plaintext, Span<byte> message)
        {
            int payloadSize = GetPayloadBufferSize(plaintext.Length);

            ArgumentOutOfRangeException.ThrowIfZero(plaintext.Length, nameof(plaintext));
            ArgumentOutOfRangeException.ThrowIfZero(message.Length, nameof(message));
            ArgumentOutOfRangeException.ThrowIfLessThan(message.Length, payloadSize, nameof(message));

            /*
             * Alloc temp buffer to copy formatted payload to data to for the encryption
             * operation. Encryption will write directly to the message buffer
             */

            using UnsafeMemoryHandle<byte> ptPayloadBuf = MemoryUtil.UnsafeAllocNearestPage<byte>(payloadSize, true);
            using UnsafeMemoryHandle<byte> hmacKeyBuf = MemoryUtil.UnsafeAlloc<byte>(NC_HMAC_KEY_SIZE, true);

            Debug.Assert(hmacKeyBuf.Length == NC_HMAC_KEY_SIZE);

            Nip44Util.FormatBuffer(plaintext, ptPayloadBuf.Span, false);

            library.EncryptNip44(
                secretKey: in _fromKey,
                publicKey: in _toKey,
                nonce32: in GetNonceRef(),
                plainText: in ptPayloadBuf.GetReference(),
                cipherText: ref MemoryMarshal.GetReference(message),
                size: (uint)payloadSize,                                //IMPORTANT: Format buffer will pad the buffer to the exact size
                hmacKeyOut32: ref hmacKeyBuf.GetReference()             //Must set the hmac key buffer
            );
            

            //Compute message mac, key should be set by the encryption operation
            library.ComputeMac(
                hmacKey32: in hmacKeyBuf.GetReference(),
                payload: in MemoryMarshal.GetReference(message),
                payloadSize: (uint)payloadSize,                         //Again set exact playload size
                hmacOut32: ref GetMacRef()
            );

            //Clear buffers
            MemoryUtil.InitializeBlock(ref hmacKeyBuf.GetReference(), hmacKeyBuf.IntLength);
            MemoryUtil.InitializeBlock(ref ptPayloadBuf.GetReference(), ptPayloadBuf.IntLength);

            return payloadSize;
        }

        private int DecryptNip44Message(ReadOnlySpan<byte> message, Span<byte> plaintext)
        {
            //Full Nip44 messages must be at-least 99 bytes in length
            ArgumentOutOfRangeException.ThrowIfLessThan(message.Length, 99, nameof(message));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(message.Length, Nip44MaxMessageSize, nameof(message));

            //Message decoder used to get the nip44 message segments
            Nip44MessageSegments msg = new(message);

            if (msg.Version != 0x02)
            {
                return 0;
            }

            SetNonce(msg.Nonce);
            SetMac(msg.Mac);

            //Temporary buffer to write decrypted plaintext data to
            using UnsafeMemoryHandle<byte> plaintextBuffer = MemoryUtil.UnsafeAllocNearestPage<byte>(msg.Ciphertext.Length, true);

            int written = DecryptPayload(msg.Ciphertext, plaintextBuffer.Span);

            Span<byte> ptOut = plaintextBuffer.AsSpan(0, written);

            //Must check message bounds before returning a range
            if (!Nip44Util.IsValidPlaintextMessage(ptOut))
            {
                throw new FormatException("Plaintext data was not properly encrypted because it was not properly formatted or decryption failed");
            }

            Range msgRange = Nip44Util.GetPlaintextRange(ptOut);
            Debug.Assert(msgRange.Start.Value > 0);
            Debug.Assert(msgRange.End.Value > 0);

            int ptLength = msgRange.End.Value - msgRange.Start.Value;

            Debug.Assert(ptLength > 0);

            //Write the wrapped plaintext (unpadded) to the output plaintext buffer
            MemoryUtil.Memmove(
                src: in plaintextBuffer.GetReference(),
                srcOffset: (uint)msgRange.Start.Value,
                dst: ref MemoryMarshal.GetReference(plaintext),
                dstOffset: 0,
                elementCount: (uint)ptLength
            );

            return ptLength;
        }

        /// <summary>
        /// Decrypts a nostr encrypted message in it's full binary from.
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="plaintext"></param>
        /// <returns>The number of bytes written to the output buffer, or an error code if an error occured during the encryption</returns>
        /// <exception cref="NotSupportedException"></exception>
        public int DecryptPayload(ReadOnlySpan<byte> payload, Span<byte> plaintext)
        {
            return Version switch
            {
                NC_ENC_VERSION_NIP44 => DecryptNip44Payload(payload, plaintext),
                _ => throw new NotSupportedException("NIP04 encryption is not supported"),
            };
        }

        private int DecryptNip44Payload(ReadOnlySpan<byte> message, Span<byte> plaintext)
        {
            ArgumentOutOfRangeException.ThrowIfZero(message.Length, nameof(message));
            ArgumentOutOfRangeException.ThrowIfZero(plaintext.Length, nameof(plaintext));

            //Validate the incoming message for a nip44 message
            ArgumentOutOfRangeException.ThrowIfLessThan(message.Length, 32, nameof(message));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(message.Length, Nip44MaxMessageSize, nameof(message));

            //Plaintext buffer must be large enough to hold the decrypted message
            ArgumentOutOfRangeException.ThrowIfLessThan(plaintext.Length, message.Length, nameof(plaintext));

            bool macValid = library.VerifyMac(
                in _fromKey,
                in _toKey,
                nonce32: in GetNonceRef(),
                mac32: in GetMacRef(),
                payload: ref MemoryMarshal.GetReference(message),
                (uint)message.Length
            );

            if (!macValid)
            {
                throw new AuthenticationException("Message MAC is invalid");
            }

            library.DecryptNip44(
                in _fromKey,
                in _toKey,
                nonce32: in GetNonceRef(),
                cipherText: in MemoryMarshal.GetReference(message),
                plainText: ref MemoryMarshal.GetReference(plaintext),
                (uint)message.Length
            );

            //Return the number of bytes written to the output buffer
            return message.Length;
        }

        private unsafe ref byte GetNonceRef()
        {
            Debug.Assert(NC_ENCRYPTION_NONCE_SIZE == sizeof(Buffer32));
            return ref Unsafe.As<Buffer32, byte>(ref _nonce32);
        }

        private unsafe ref byte GetMacRef()
        {
            Debug.Assert(NC_ENCRYPTION_MAC_SIZE == sizeof(Buffer32));
            return ref Unsafe.As<Buffer32, byte>(ref _mac32);
        }

        protected override void Free()
        {
            //Zero all internal memory
            MemoryUtil.ZeroStruct(ref _fromKey);
            MemoryUtil.ZeroStruct(ref _toKey);
            MemoryUtil.ZeroStruct(ref _nonce32);
            MemoryUtil.ZeroStruct(ref _mac32);
        }

        /// <summary>
        /// Initializes a new <see cref="NostrMessageCipher"/> with the nip44 encryption
        /// method.
        /// </summary>
        /// <param name="lib">The nostr crypto implementation instance to use</param>
        /// <returns>The intialzied message instance</returns>
        public static NostrMessageCipher CreateNip44Cipher(INostrCrypto lib) 
            => new(lib, NCNip44EncryptionVersion.Instance);
       

        [StructLayout(LayoutKind.Sequential, Size = 32)]
        unsafe struct Buffer32
        {
            fixed byte value[32];
        }
    }

}
