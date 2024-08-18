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

using VNLib.Utils.Cryptography.Noscrypt.Encryption;

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
        /// Allocates a new cipher instance with the supplied options.
        /// </summary>
        /// <param name="version">The cipher specification version</param>
        /// <param name="flags">The cipher initialziation flags</param>
        /// <returns>The cipher instance</returns>
        NoscryptCipher AllocCipher(NoscryptCipherVersion version, NoscryptCipherFlags flags);

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
    }
}
