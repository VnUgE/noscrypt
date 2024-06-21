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

using Microsoft.Win32.SafeHandles;

using VNLib.Utils.Extensions;
using VNLib.Utils.Memory;

using VNLib.Utils.Cryptography.Noscrypt.@internal;
using static VNLib.Utils.Cryptography.Noscrypt.NoscryptLibrary;

using NCResult = System.Int64;

namespace VNLib.Utils.Cryptography.Noscrypt
{
    /// <summary>
    /// The noscrypt library context
    /// </summary>
    public sealed class NCContext : SafeHandleZeroOrMinusOneIsInvalid
    {
        private readonly IUnmangedHeap Heap;

        /// <summary>
        /// The library this context was created from
        /// </summary>
        public NoscryptLibrary Library { get; }

        internal NCContext(IntPtr handle, IUnmangedHeap heap, NoscryptLibrary library) :base(true)
        {
            ArgumentNullException.ThrowIfNull(heap);
            ArgumentNullException.ThrowIfNull(library);
            
            Heap = heap;
            Library = library;

            //Store the handle
            SetHandle(handle);
        }

        /// <summary>
        /// Reinitializes the context with the specified entropy
        /// </summary>
        /// <param name="entropy">The randomness buffer used to randomize the context</param>
        /// <param name="size">The random data buffer size (must be 32 bytes)</param>
        public unsafe void Reinitalize(ref byte entropy, int size)
        {
            //Entropy must be exactly 32 bytes
            ArgumentOutOfRangeException.ThrowIfNotEqual(size, NC_CTX_ENTROPY_SIZE);

            this.ThrowIfClosed();
            fixed (byte* p = &entropy)
            {
                NCResult result = Library.Functions.NCReInitContext.Invoke(handle, p);
                NCUtil.CheckResult<FunctionTable.NCReInitContextDelegate>(result, true);
            }
        }

        ///<inheritdoc/>
        protected override bool ReleaseHandle()
        {
            if (!Library.IsClosed)
            {
                //destroy the context
                Library.Functions.NCDestroyContext.Invoke(handle);
                Trace.WriteLine($"Destroyed noscrypt context 0x{handle:x}");
            }

            //Free the handle
            return Heap.Free(ref handle);
        }
    }
}
