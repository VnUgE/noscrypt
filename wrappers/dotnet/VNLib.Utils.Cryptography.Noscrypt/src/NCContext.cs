// Copyright (C) 2026 Vaughn Nugent
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

using VNLib.Utils.Memory;

namespace VNLib.Utils.Cryptography.Noscrypt
{
    /// <summary>
    /// Noscrypt library context state object. Wraps the nccontext state memory
    /// and managed it's lifecycle.
    /// <para>
    /// This context is considered thread-safe for all noscrypt 
    /// library operations except those that explicitly state otherwise.
    /// </para>
    /// </summary>
    public sealed class NCContext : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal readonly IUnmanagedHeap Heap;

        /// <summary>
        /// The library this context was created from
        /// </summary>
        public Noscrypt Library { get; }

        internal NCContext(IntPtr handle, IUnmanagedHeap heap, Noscrypt library) : base(ownsHandle: true)
        {
            ArgumentNullException.ThrowIfNull(heap);
            ArgumentNullException.ThrowIfNull(library);

            Heap = heap;
            Library = library;

            //Store the handle
            SetHandle(handle);
        }

        ///<inheritdoc/>
        protected override bool ReleaseHandle()
        {
            try
            {
                Library.Functions.NCDestroyContext.Invoke(handle);
                Trace.WriteLine($"Destroyed noscrypt context 0x{handle:x}");
            }
            catch (ObjectDisposedException)
            {
                // swallow ODE from disposed library wrapper, it should still be safe
                // to free the handle. The Library.Functions may throw ode if it's disposed before
                // this context is released.
            }

            // Free the handle (should clear ref and set handle to 0)
            return Heap.Free(ref handle);
        }
    }
}
