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

namespace VNLib.Utils.Cryptography.Noscrypt
{
    public interface INostrCrypto
    {

        /// <summary>
        /// Gets a nostr public key from a secret key.
        /// </summary>
        /// <param name="secretKey">A reference to the secret key to get the public key from</param>
        /// <param name="publicKey">A reference to the public key structure to write the recovered key to</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        void GetPublicKey(ref readonly NCSecretKey secretKey, ref NCPublicKey publicKey);

        /// <summary>
        /// Validates a secret key is in a valid format. 
        /// </summary>
        /// <param name="secretKey">A readonly reference to key structure to validate</param>
        /// <returns>True if the key is consiered valid against the secp256k1 curve</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        bool ValidateSecretKey(ref readonly NCSecretKey secretKey);

        /// <summary>
        /// Signs the supplied data with the secret key and random32 nonce, then writes
        /// the message signature to the supplied sig64 buffer.
        /// </summary>
        /// <param name="secretKey">The secret key used to sign the message</param>
        /// <param name="random32">A highly secure random nonce used to seed the signature</param>
        /// <param name="data">A pointer to the first byte in the message to sign</param>
        /// <param name="dataSize">The size of the message in bytes</param>
        /// <param name="sig64">A pointer to the first byte of a 64 byte buffer used to write the message signature to</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        void SignData(
            ref readonly NCSecretKey secretKey, 
            ref readonly byte random32, 
            ref readonly byte data, 
            uint dataSize, 
            ref byte sig64
        );

        /// <summary>
        /// Performs cryptographic verification of the supplied data 
        /// against the supplied public key.
        /// </summary>
        /// <param name="pubKey">The signer's public key</param>
        /// <param name="data">A pointer to the first byte in the message to sign</param>
        /// <param name="dataSize">The number of bytes in the message</param>
        /// <param name="sig64">A pointer to the signature buffer</param>
        /// <returns>True if the signature could be verified against the public key. False otherwise</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        bool VerifyData(
            ref readonly NCPublicKey pubKey, 
            ref readonly byte data, 
            uint dataSize, 
            ref readonly byte sig64
        );

        /// <summary>
        /// Computes a nip44 message authentication code (MAC) using the supplied key and payload.
        /// </summary>
        /// <param name="hmacKey32">The key returned during a 
        /// <see cref="Encrypt(ref readonly NCSecretKey, ref readonly NCPublicKey, ref readonly byte, ref readonly byte, ref byte, uint, ref byte)"/>
        /// </param>
        /// <param name="payload">A pointer to a buffer </param>
        /// <param name="payloadSize">The size of the buffer to compute the mac of, in bytes</param>
        /// <param name="hmacOut32">A pointer to the 32byte buffer to write the mac to</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        void ComputeMac(
            ref readonly byte hmacKey32,
            ref readonly byte payload,
            uint payloadSize,
            ref byte hmacOut32
        );

        /// <summary>
        /// Verifies a nip44 message authentication code (MAC) against the supplied key and payload. 
        /// </summary>
        /// <param name="secretKey">A pointer to the receiver's secret key</param>
        /// <param name="publicKey">A pointer to senders the public key</param>
        /// <param name="nonce32">A pointer to the 32byte nonce buffer</param>
        /// <param name="mac32">A pointer to the 32byte message buffer</param>
        /// <param name="payload">A pointer to the message buffer</param>
        /// <param name="payloadSize">The size in bytes of the payload buffer</param>
        /// <returns>True if the message authentication code (MAC) matches, false otherwise </returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        bool VerifyMac(
            ref readonly NCSecretKey secretKey, 
            ref readonly NCPublicKey publicKey, 
            ref readonly byte nonce32,
            ref readonly byte mac32,
            ref readonly byte payload,
            uint payloadSize
        );

        /// <summary>
        /// Encrypts a message using the supplied secret key, public key, and nonce. When this function
        /// returns, the cipherText buffer will contain the encrypted message, and the hmacKeyOut32 buffer
        /// will contain the key used to compute the message authentication code (MAC).
        /// <para>
        /// NOTE: The cipherText buffer must be at least as large as the plaintext buffer. The 
        /// size parameter must be the size of the number of bytes to encrypt.
        /// </para>
        /// </summary>
        /// <param name="secretKey">A pointer to the receiver's secret key</param>
        /// <param name="publicKey">A pointer to senders the public key</param>
        /// <param name="nonce32">A pointer to the 32byte nonce used for message encryption</param>
        /// <param name="plainText">A pointer to the plaintext buffer to encrypt</param>
        /// <param name="cipherText">A pointer to the cyphertext buffer to write encrypted data to (must be as large or larger than the plaintext buffer)</param>
        /// <param name="size">The size of the data to encrypt</param>
        /// <param name="hmacKeyOut32"></param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        void EncryptNip44(
            ref readonly NCSecretKey secretKey, 
            ref readonly NCPublicKey publicKey, 
            ref readonly byte nonce32, 
            ref readonly byte plainText, 
            ref byte cipherText,
            uint size,
            ref byte hmacKeyOut32
        );

        /// <summary>
        /// Decrypts a message using the supplied secret key, public key, and the original message 
        /// nonce.
        /// </summary>
        /// <param name="secretKey">A pointer to the receiver's secret key</param>
        /// <param name="publicKey">A pointer to senders the public key</param>
        /// <param name="nonce32">A pointer to the 32byte nonce used for message encryption</param>
        /// <param name="plainText">A pointer to the plaintext buffer to write plaintext data to (must be as large or larger than the ciphertext buffer)</param>
        /// <param name="cipherText">A pointer to the cyphertext buffer to read encrypted data from</param>
        /// <param name="size">The size of the buffer to decrypt</param>
        void DecryptNip44(
            ref readonly NCSecretKey secretKey, 
            ref readonly NCPublicKey publicKey, 
            ref readonly byte nonce32, 
            ref readonly byte cipherText, 
            ref byte plainText,
            uint size
        );
    }
}
