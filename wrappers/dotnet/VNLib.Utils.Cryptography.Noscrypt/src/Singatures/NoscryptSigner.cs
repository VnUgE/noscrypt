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

using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Utils.Cryptography.Noscrypt;
using VNLib.Utils.Cryptography.Noscrypt.Random;
using static VNLib.Utils.Cryptography.Noscrypt.NoscryptLibrary;

namespace VNLib.Utils.Cryptography.Noscrypt.Singatures
{

    /// <summary>
    /// A simple wrapper class to sign nostr message data using 
    /// the noscrypt library
    /// </summary>
    /// <param name="noscrypt">The noscrypt library instance</param>
    /// <param name="random">A random entropy pool used to source random data for signature entropy</param>
    public class NoscryptSigner(NCContext context, IRandomSource random)
    {
        /// <summary>
        /// Gets the size of the buffer required to hold the signature
        /// </summary>
        public static int SignatureBufferSize => NC_SIGNATURE_SIZE;

        /// <summary>
        /// Signs a message using the specified private key and message data
        /// </summary>
        /// <param name="hexPrivateKey">The hexadecimal private key used to sign the message</param>
        /// <param name="message">The message data to sign</param>
        /// <param name="format">A encoder used to convert the signature data to an encoded string</param>
        /// <returns>The string encoded nostr signature</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public string SignData(string hexPrivateKey, ReadOnlySpan<byte> message, INostrSignatureEncoder? format = null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(hexPrivateKey);
            ArgumentOutOfRangeException.ThrowIfNotEqual(hexPrivateKey.Length / 2, NC_SEC_KEY_SIZE, nameof(hexPrivateKey));

            //Have to allocate array unfortunately
            byte[] privKey = Convert.FromHexString(hexPrivateKey);
            try
            {
                return SignData(privKey.AsSpan(), message, format);
            }
            finally
            {
                //Always zero key beofre leaving
                MemoryUtil.InitializeBlock(privKey);
            }
        }

        /// <summary>
        /// Signs a message using the specified secret key and message data
        /// </summary>
        /// <param name="secretKey">The secret key data buffer</param>
        /// <param name="message">The message data to sign</param>
        /// <param name="format">A encoder used to convert the signature data to an encoded string</param>
        /// <returns>The string encoded nostr signature</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public string SignData(
            ReadOnlySpan<byte> secretKey,
            ReadOnlySpan<byte> message,
            INostrSignatureEncoder? format = null
        )
        {
            return SignData(
                in NCKeyUtil.AsSecretKey(secretKey), 
                message, 
                format
            );
        }

        /// <summary>
        /// Signs a message using the specified secret key and message data
        /// </summary>
        /// <param name="secretkey">A reference to the secret key structurer</param>
        /// <param name="message">The message data to sign</param>
        /// <param name="format">A encoder used to convert the signature data to an encoded string</param>
        /// <returns>The string encoded nostr signature</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public string SignData(
            ref readonly NCSecretKey secretkey,
            ReadOnlySpan<byte> message,
            INostrSignatureEncoder? format = null
        )
        {
            //Default to hex encoding because that is the default NIP-01 format
            format ??= HexSignatureEncoder.Instance;

            Span<byte> sigBuffer = stackalloc byte[SignatureBufferSize];

            SignData(message, sigBuffer);

            return format.GetString(sigBuffer);
        }


        /// <summary>
        /// Signs a message using the specified secret key and message data
        /// </summary>
        /// <param name="secretkey">A reference to the secret key structurer</param>
        /// <param name="data">The message data to sign</param>
        /// <param name="signature">A buffer to write signature data to</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public void SignData(
            ref readonly NCSecretKey secretkey,
            ReadOnlySpan<byte> data,
            Span<byte> signature
        )
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(signature.Length, NC_SIGNATURE_SIZE, nameof(signature));

            //Signature generation required random entropy to be secure
            Span<byte> entropy = stackalloc byte[NC_SIG_ENTROPY_SIZE];
            random.GetRandomBytes(entropy);

            NCSignatureUtil.SignData(
                context, 
                in secretkey, 
                entropy, 
                data, 
                signature
            );
        }

        public bool VerifyData(
              ReadOnlySpan<byte> publicKey,
              ReadOnlySpan<byte> data,
              ReadOnlySpan<byte> sig
          )
        {
            return VerifyData(
                in NCKeyUtil.AsPublicKey(publicKey), 
                data, 
                sig
            );
        }

        public bool VerifyData(
            ref readonly NCPublicKey pk, 
            ReadOnlySpan<byte> data, 
            ReadOnlySpan<byte> sig
        )
        {
            return NCSignatureUtil.VerifyData(context, in pk, data, sig);
        }
    }

}
