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

using VNLib.Utils.Extensions;
using VNLib.Utils.Memory;

using static VNLib.Utils.Cryptography.Noscrypt.LibNoscrypt;

namespace VNLib.Utils.Cryptography.Noscrypt
{

    public sealed class NostrEncryptedMessage(IEncryptionVersion version, INostrCrypto lib) : VnDisposeable
    {
        private readonly INostrCrypto library = lib;

        private NCSecretKey _fromKey;
        private NCPublicKey _toKey;       
        private Buffer32 _nonce32;

        /// <summary>
        /// The message encryption version used by this instance
        /// </summary>
        public uint Version { get; } = version.Version;

        /// <summary>
        /// The message nonce created during encryption event
        /// </summary>
        public unsafe Span<byte> Nonce
        {
            get
            {
                Debug.Assert(NC_ENCRYPTION_NONCE_SIZE == sizeof(Buffer32));
                return MemoryMarshal.CreateSpan(ref GetNonceRef(), sizeof(Buffer32));
            }
        }

        /// <summary>
        /// Gets the size of the buffer required to encrypt the specified data size
        /// </summary>
        /// <param name="dataSize">The size of the message raw plaintext message to send</param>
        /// <returns>The minimum number of bytes required for message encryption output</returns>
        /// <exception cref="NotSupportedException"></exception>
        public int GetOutputBufferSize(int dataSize) 
            => version.CalcBufferSize(dataSize);

        /// <summary>
        /// Sets the encryption secret key for the message
        /// </summary>
        /// <param name="secKey">The secret key buffer</param>
        /// <returns>The current instance for chaining</returns>
        /// <exception cref="ArgumentException"></exception>
        public NostrEncryptedMessage SetSecretKey(ReadOnlySpan<byte> secKey) 
            => SetSecretKey(in NCUtil.AsSecretKey(secKey));

        /// <summary>
        /// Sets the encryption secret key for the message
        /// </summary>
        /// <param name="secKey">The secret key structure to copy</param>
        /// <returns>The current instance for chaining</returns>
        /// <exception cref="ArgumentException"></exception>
        public NostrEncryptedMessage SetSecretKey(ref readonly NCSecretKey secKey)
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
        public NostrEncryptedMessage SetPublicKey(ReadOnlySpan<byte> pubKey) 
            => SetPublicKey(in NCUtil.AsPublicKey(pubKey));

        /// <summary>
        /// Assigns the public key used to encrypt the message as the 
        /// receiver of the message
        /// </summary>
        /// <param name="pubKey">The user's public key receiving the message</param>
        /// <returns>The current instance for chaining</returns>
        /// <exception cref="ArgumentException"></exception>
        public NostrEncryptedMessage SetPublicKey(ref readonly NCPublicKey pubKey)
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
        public NostrEncryptedMessage SetNonce(ReadOnlySpan<byte> nonce)
        {
            MemoryUtil.CopyStruct(nonce, ref _nonce32);
            return this;
        }

        /// <summary>
        /// Assigns a random nonce using the specified random source
        /// </summary>
        /// <param name="rng">The random source to genrate a random nonce from</param>
        /// <returns>The current instance for chaining</returns>
        public NostrEncryptedMessage SetRandomNonce(IRandomSource rng)
        {
            rng.GetRandomBytes(Nonce);
            return this;
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
        public int EncryptMessage(ReadOnlySpan<byte> plaintext, Span<byte> message, Span<byte> macOut32)
        {
            return Version switch
            {
                NC_ENC_VERSION_NIP44 => EncryptNip44(plaintext, message, macOut32),
                _ => throw new NotSupportedException("NIP04 encryption is not supported"),
            };
        }

        private int EncryptNip44(ReadOnlySpan<byte> plaintext, Span<byte> message, Span<byte> macOut32)
        {
            int payloadSize = GetOutputBufferSize(plaintext.Length);

            ArgumentOutOfRangeException.ThrowIfZero(plaintext.Length, nameof(plaintext));
            ArgumentOutOfRangeException.ThrowIfZero(message.Length, nameof(message));
            ArgumentOutOfRangeException.ThrowIfLessThan(message.Length, payloadSize, nameof(message));
            ArgumentOutOfRangeException.ThrowIfLessThan(macOut32.Length, NC_ENCRYPTION_MAC_SIZE, nameof(macOut32));

            /*
             * Alloc temp buffer to copy formatted payload to data to for the encryption
             * operation. Encryption will write directly to the message buffer
             */

            using UnsafeMemoryHandle<byte> ptPayloadBuf = MemoryUtil.UnsafeAllocNearestPage<byte>(payloadSize, true);
            using UnsafeMemoryHandle<byte> hmacKeyBuf = MemoryUtil.UnsafeAlloc<byte>(NC_HMAC_KEY_SIZE, true);
            Debug.Assert(hmacKeyBuf.Length == NC_HMAC_KEY_SIZE);

            Nip44Util.FormatBuffer(plaintext, ptPayloadBuf.Span, false);

            library.EncryptNip44(
                in _fromKey,
                in _toKey,
                in GetNonceRef(),
                in ptPayloadBuf.GetReference(),
                ref MemoryMarshal.GetReference(message),
                (uint)payloadSize,                  //IMPORTANT: Format buffer will pad the buffer to the exact size
                ref hmacKeyBuf.GetReference()       //Must set the hmac key buffer
            );

            //Safe to clear the plain text copy buffer
            MemoryUtil.InitializeBlock(
                ref ptPayloadBuf.GetReference(),
                ptPayloadBuf.GetIntLength()
            );


            //Compute message mac, key should be set by the encryption operation
            library.ComputeMac(
                in hmacKeyBuf.GetReference(),
                in MemoryMarshal.GetReference(message),
                (uint)payloadSize,  //Again set exact playload size
                ref MemoryMarshal.GetReference(macOut32)
            );

            //Safe to clear the hmac key buffer
            MemoryUtil.InitializeBlock(
                ref hmacKeyBuf.GetReference(),
                hmacKeyBuf.GetIntLength()
            );

            return payloadSize;
        }

        private ref byte GetNonceRef() => ref Unsafe.As<Buffer32, byte>(ref _nonce32);      

        protected override void Free()
        {
            //Zero all internal memory
            MemoryUtil.ZeroStruct(ref _fromKey);
            MemoryUtil.ZeroStruct(ref _toKey);
            MemoryUtil.ZeroStruct(ref _nonce32);
        }

        /// <summary>
        /// Initializes a new <see cref="NostrEncryptedMessage"/> with the nip44 encryption
        /// method.
        /// </summary>
        /// <param name="lib">The nostr crypto implementation instance to use</param>
        /// <returns>The intialzied message instance</returns>
        public static NostrEncryptedMessage CreateNip44Cipher(INostrCrypto lib) 
            => new(NCNip44EncryptionVersion.Instance, lib);
       

        [StructLayout(LayoutKind.Sequential, Size = 32)]
        unsafe struct Buffer32
        {
            fixed byte value[32];
        }
    }

}
