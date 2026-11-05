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
using System.Runtime.InteropServices;

using VNLib.Utils.Native;
using VNLib.Utils.Resources;

namespace VNLib.Utils.Cryptography.Noscrypt.Random
{

    /// <summary>
    /// A wrapper class for an unmanaged random source that conforms to the <see cref="IRandomSource"/> interface
    /// </summary>
    /// <remarks>
    /// Creates the unmanaged random source from the given library by loading
    /// the function symbol and holding a reference to the library. The library
    /// handle count is incremented on success.
    /// </remarks>
    /// <param name="lib">The library handle to wrap</param>
    /// <exception cref="ObjectDisposedException"></exception>
    /// <exception cref="EntryPointNotFoundException"></exception>
    public class UnmanagedRandomSource(Owned<SafeLibraryHandle> library) : VnDisposeable, IRandomSource
    {
        /// <summary>
        /// The explicit name of the unmanaged random function to get random bytes
        /// </summary>
        public const string RngFunctionName = "GetRandomBytes";

        unsafe delegate void UnmanagedRandomSourceDelegate(byte* buffer, int size);

        private readonly Owned<SafeLibraryHandle> _library = library;
        private readonly SafeMethodHandle<UnmanagedRandomSourceDelegate> _getRandomBytes 
            = library.Value.GetFunction<UnmanagedRandomSourceDelegate>(RngFunctionName);

        /// <summary>
        /// Loads the unmanaged random source from the given library 
        /// and attempts to get the random bytes method <see cref="RngFunctionName"/>
        /// </summary>
        /// <param name="path"></param>
        /// <param name="search"></param>
        /// <returns>The wrapped library that conforms to the <see cref="IRandomSource"/></returns>
        public static UnmanagedRandomSource LoadLibrary(string path, DllImportSearchPath search)
        {
            //Try to load the library
            SafeLibraryHandle lib = SafeLibraryHandle.LoadLibrary(path, search);
            try
            {
                return new UnmanagedRandomSource(lib, ownsHandle: true);
            }
            catch
            {
                //release lib
                lib.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Creates the unmanaged random source from the given library
        /// </summary>
        /// <param name="lib">The library handle to wrap</param>
        /// <exception cref="ObjectDisposedException"></exception>
        /// <exception cref="EntryPointNotFoundException"></exception>
        public UnmanagedRandomSource(SafeLibraryHandle lib, bool ownsHandle)
            : this(new(lib, ownsHandle))
        { }

        ///<inheritdoc/>
        public unsafe void GetRandomBytes(Span<byte> buffer)
        {
            // Fix buffer and call unmanaged method
            fixed (byte* ptr = &MemoryMarshal.GetReference(buffer))
            {
                _getRandomBytes.Method!.Invoke(ptr, buffer.Length);
            }
        }

        ///<inheritdoc/>
        protected override void Free()
        {
            // Dispose safe method handle releasing library count
            _getRandomBytes.Dispose();
            _library.Dispose();
        }
    }
}
