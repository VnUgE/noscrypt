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
using System.Threading;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using VNLib.Utils.Memory;
using VNLib.Utils.Cryptography.Noscrypt.Random;
using static VNLib.Utils.Cryptography.Noscrypt.NoscryptLibrary;

namespace VNLib.Utils.Cryptography.Noscrypt.Encryption
{
    /// <summary>
    /// The noscrypt util cipher wapper 
    /// </summary>
    /// <param name="ctx"></param>
    /// <param name="flags">Cipher creation flags</param>
    /// <param name="version">The cipher specification version</param>
    public sealed class NoscryptCipher(NCContext ctx, NoscryptCipherVersion version, NoscryptCipherFlags flags) : VnDisposeable
    {
        private IMemoryHandle<byte>? _ivBuffer;
        private readonly nint _cipher = NCUtilCipher.Alloc(ctx, (uint)version, (uint)flags);

        /// <summary>
        /// The cipher standard version used by this instance
        /// </summary>
        public NoscryptCipherVersion Version => version;

        /// <summary>
        /// Gets the flags set for the cipher instance
        /// </summary>
        public uint GetFlags() => NCUtilCipher.GetFlags(ctx, _cipher);

        /// <summary>
        /// Gets the cipher's initilaization vector size (or nonce)
        /// </summary>
        /// <returns>The size of the IV in bytes</returns>
        public int GetIvSize() => NCUtilCipher.GetIvSize(ctx, _cipher);

        /// <summary>
        /// Gets the internal heap buffer that holds the cipher's initalization
        /// vector.
        /// </summary>
        /// <returns>The mutable span of the cipher's IV buffer</returns>
        public Span<byte> IvBuffer
        {
            get => LazyInitializer.EnsureInitialized(ref _ivBuffer, AllocIvBuffer).Span;
        }

        /// <summary>
        /// Sets the cipher's initialization vector to a random value using
        /// the specified random source
        /// </summary>
        /// <param name="rng">The random source</param>
        public void SetRandomIv(IRandomSource rng)
        {
            ArgumentNullException.ThrowIfNull(rng);
            rng.GetRandomBytes(IvBuffer);
        }

        /// <summary>
        /// Performs the cipher operation on the input data using the specified
        /// local and remote keys. 
        /// </summary>
        /// <param name="localKey">The secret key of the local user</param>
        /// <param name="remoteKey">The public key of the remote user</param>
        /// <param name="inputData">A pointer to the first byte in the buffer sequence</param>
        /// <param name="inputSize">The size of the input buffer in bytes</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <remarks>
        /// If the <see cref="NoscryptCipherFlags.Reusable"/> flag is
        /// set, this function may be considered independent and called repeatedly.
        /// </remarks>
        public unsafe void Update(
            ref readonly NCSecretKey localKey,
            ref readonly NCPublicKey remoteKey,
            ref readonly byte inputData,
            uint inputSize
        )
        {
            if (Unsafe.IsNullRef(in localKey))
            {
                throw new ArgumentNullException(nameof(localKey));
            }

            if (Unsafe.IsNullRef(in remoteKey))
            {
                throw new ArgumentNullException(nameof(remoteKey));
            }

            if (Unsafe.IsNullRef(in inputData))
            {
                throw new ArgumentNullException(nameof(inputData));
            }

            /*
             * Initializing the cipher requires the context holding a pointer
             * to the input data, so it has to be pinned in a fixed statment 
             * for the duration of the update operation.
             * 
             * So init and update must be done as an atomic operation.
             * 
             * If ciphers have the Reusable flag set this function may be called
             * repeatedly. The results of this operation can be considered
             * independent.
             */

            fixed (byte* inputPtr = &inputData)
            {
                NCUtilCipher.InitCipher(ctx, _cipher, inputPtr, inputSize);

                NCUtilCipher.Update(ctx, _cipher, in localKey, in remoteKey);
            }
        }

        /// <summary>
        /// Performs the cipher operation on the input data using the specified
        /// local and remote keys.
        /// </summary>
        /// <param name="localKey">The secret key of the local user</param>
        /// <param name="remoteKey">The public key of the remote user</param>
        /// <param name="input">The buffer sequence to read the input data from</param>
        /// <exception cref="ArgumentNullException"></exception>
        public void Update(
            ref readonly NCSecretKey localKey,
            ref readonly NCPublicKey remoteKey,
            ReadOnlySpan<byte> input
        )
        {
            Update(
                in localKey,
                in remoteKey,
                inputData: ref MemoryMarshal.GetReference(input),   //If empty, null ref will throw
                inputSize: (uint)input.Length
            );
        }

        /// <summary>
        /// Gets the size of the output buffer required to read the cipher output
        /// </summary>
        /// <returns>The size of the output in bytes</returns>
        public int GetOutputSize() => checked((int)NCUtilCipher.GetOutputSize(ctx, _cipher));

        /// <summary>
        /// Reads the output data from the cipher into the specified buffer
        /// </summary>
        /// <param name="outputData">A reference to the first byte in the buffer sequence</param>
        /// <param name="size">The size of the buffer sequence</param>
        /// <returns>The number of bytes written to the buffer</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public int ReadOutput(ref byte outputData, int size)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(size, GetOutputSize());

            return checked((int)NCUtilCipher.ReadOutput(ctx, _cipher, ref outputData, (uint)size));
        }

        /// <summary>
        /// Reads the output data from the cipher into the specified buffer
        /// </summary>
        /// <param name="buffer">The buffer sequence to write output data to</param>
        /// <returns>The number of bytes written to the buffer</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public int ReadOutput(Span<byte> buffer)
        {
            return ReadOutput(
                ref MemoryMarshal.GetReference(buffer),
                buffer.Length
            );
        }

        private IMemoryHandle<byte> AllocIvBuffer()
        {
            //Use the context heap to allocate the internal iv buffer
            MemoryHandle<byte> buffer = MemoryUtil.SafeAlloc<byte>(ctx.Heap, GetIvSize(), zero: true);

            try
            {
                /*
                 * Assign the buffer reference to the cipher context
                 * 
                 * NOTE: This pointer will be held as long as the cipher 
                 * context is allocated. So the buffer must be held until
                 * the cipher is freed. Because of this an umnanaged heap 
                 * buffer is required so we don't need to pin managed memory
                 * nor worry about the GC moving the buffer.
                 */
                NCUtilCipher.SetProperty(
                   ctx,
                   _cipher,
                   NC_ENC_SET_IV,
                   ref buffer.GetReference(),
                   (uint)buffer.Length
               );
            }
            catch
            {
                buffer.Dispose();
                throw;
            }

            return buffer;
        }

        ///<inheritdoc/>
        protected override void Free()
        {
            NCUtilCipher.Free(ctx, _cipher);
            _ivBuffer?.Dispose();
        }
    }

}
