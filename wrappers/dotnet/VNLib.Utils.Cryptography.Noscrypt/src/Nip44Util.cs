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
using System.Buffers.Binary;
using System.Runtime.InteropServices;

using VNLib.Utils.Memory;

using static VNLib.Utils.Cryptography.Noscrypt.LibNoscrypt;

namespace VNLib.Utils.Cryptography.Noscrypt
{

    /// <summary>
    /// Provides a set of utility methods for working with the Noscrypt library
    /// </summary>
    public static class Nip44Util
    {
        /// <summary>
        /// Calculates the required NIP44 encryption buffer size for 
        /// the specified input data size
        /// </summary>
        /// <param name="dataSize">The size (in bytes) of the encoded data to encrypt</param>
        /// <returns>The exact size of the padded buffer output</returns>
        public static int CalcBufferSize(int dataSize)
        {
            /*
             * Taken from https://github.com/nostr-protocol/nips/blob/master/44.md
             * 
             * Not gonna lie, kinda dumb branches. I guess they want to save space
             * with really tiny messages... Dunno, but whatever RTFM
             */

            //Min message size is 32 bytes
            int minSize = Math.Max(dataSize, 32);

            //find the next power of 2 that will fit the min size
            int nexPower = 1 << ((int)Math.Log2(minSize - 1)) + 1;

            int chunk = nexPower <= 256 ? 32 : nexPower / 8;

            return (chunk * ((int)Math.Floor((double)((minSize - 1) / chunk)) + 1)) + sizeof(ushort);
        }

        /// <summary>
        /// Calculates the final buffer size required to hold the encrypted data
        /// </summary>
        /// <param name="dataSize">The size (in bytes) of plaintext data to encrypt</param>
        /// <returns>The number of bytes required to store the final nip44 message</returns>
        public static int CalcFinalBufferSize(int dataSize)
        {
            /* version + nonce + payload + mac */
            return CalcBufferSize(dataSize) + NC_ENCRYPTION_NONCE_SIZE + NC_ENCRYPTION_MAC_SIZE + 1;
        }

        /// <summary>
        /// Formats the plaintext data into a buffer that can be properly encrypted. 
        /// The output buffer must be zeroed, or can be zeroed using the 
        /// <paramref name="zeroOutput"/> parameter. Use <see cref="CalcBufferSize(uint)"/> 
        /// to determine the required output buffer size.
        /// </summary>
        /// <param name="plaintextData">A buffer containing plaintext data to copy to the output</param>
        /// <param name="output">The output data buffer to format</param>
        /// <param name="zeroOutput">A value that indicates if the buffer should be zeroed before use</param>
        public static void FormatBuffer(ReadOnlySpan<byte> plaintextData, Span<byte> output, bool zeroOutput)
        {
            //First zero out the buffer
            if (zeroOutput)
            {
                MemoryUtil.InitializeBlock(output);
            }

            //Make sure the output buffer is large enough so we dont overrun it
            ArgumentOutOfRangeException.ThrowIfLessThan(output.Length, plaintextData.Length + sizeof(ushort), nameof(output));

            //Write the data size to the first 2 bytes
            ushort dataSize = (ushort)plaintextData.Length;
            BinaryPrimitives.WriteUInt16BigEndian(output, dataSize);

            //Copy the plaintext data to the output buffer after the data size
            MemoryUtil.Memmove(
                in MemoryMarshal.GetReference(plaintextData),
                0,
                ref MemoryMarshal.GetReference(output),
                 sizeof(ushort),
                (uint)plaintextData.Length
            );

            //We assume the remaining buffer is zeroed out
        }

        public static ReadOnlySpan<byte> GetNonceFromPayload(ReadOnlySpan<byte> message)
        {
            //The nonce is 32 bytes following the 1st byte version number of the message
            return message.Slice(1, NC_ENCRYPTION_NONCE_SIZE);
        }

        public static ReadOnlySpan<byte> GetCiphertextFromPayload(ReadOnlySpan<byte> message)
        {
            //Message is between the nonce and the trailing mac
            int payloadSize = message.Length - (1 + NC_ENCRYPTION_NONCE_SIZE + NC_ENCRYPTION_MAC_SIZE);
            return message.Slice(1 + NC_ENCRYPTION_NONCE_SIZE, payloadSize);
        }

        public static ReadOnlySpan<byte> GetMacFromPayload(ReadOnlySpan<byte> message)
        {
            //The mac is the last 32 bytes of the message
            return message[^NC_ENCRYPTION_MAC_SIZE..];
        }

        public static ReadOnlySpan<byte> GetNonceAndCiphertext(ReadOnlySpan<byte> message)
        {
            //The nonce is 32 bytes following the 1st byte version number of the message
            return message.Slice(1, NC_ENCRYPTION_NONCE_SIZE + GetCiphertextFromPayload(message).Length);
        }

        public static byte GetMessageVersion(ReadOnlySpan<byte> message)
        {
            //The first byte is the message version
            return message[0];
        }

        public static ReadOnlySpan<byte> GetPlaintextMessage(ReadOnlySpan<byte> plaintextPayload)
        {
            ushort ptLength = BinaryPrimitives.ReadUInt16BigEndian(plaintextPayload);
            return plaintextPayload.Slice(sizeof(ushort), ptLength);
        }

    }

}
