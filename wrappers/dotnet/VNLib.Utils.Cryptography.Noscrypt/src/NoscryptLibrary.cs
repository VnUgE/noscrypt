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
using System.Runtime.InteropServices;

using VNLib.Utils.Memory;
using VNLib.Utils.Native;
using VNLib.Utils.Extensions;

using VNLib.Utils.Cryptography.Noscrypt.Random;
using VNLib.Utils.Cryptography.Noscrypt.@internal;

using NCResult = System.Int64;

namespace VNLib.Utils.Cryptography.Noscrypt
{

    /// <summary>
    /// Initializes the native library and provides access to the native functions
    /// </summary>
    /// <param name="Library">An existing noscrypt library handle</param>
    /// <param name="OwnsHandle">A value that indicates if the instance owns the library handle</param>
    public unsafe sealed class NoscryptLibrary(SafeLibraryHandle Library, bool OwnsHandle) : VnDisposeable
    {
        public const string NoscryptDefaultLibraryName = "noscrypt";

        //Constant values match the noscrypt.h header
        public const int NC_SEC_KEY_SIZE                = 0x20;
        public const int NC_SEC_PUBKEY_SIZE             = 0x20;
        public const int NC_PUBKEY_SIZE                 = 0x20;
        public const int NC_SIGNATURE_SIZE              = 0x40;
        public const int NC_CONV_KEY_SIZE               = 0x20;
        public const int NC_MESSAGE_KEY_SIZE            = 0x20;
        public const int NC_HMAC_KEY_SIZE               = 0x20;
        public const int NC_ENCRYPTION_MAC_SIZE         = 0x20;
        public const int NC_CONVERSATION_KEY_SIZE       = 0x20;
        public const int NC_CTX_ENTROPY_SIZE            = 0x20;
        public const int NC_SIG_ENTROPY_SIZE            = 0x20;

        public const uint NC_ENC_VERSION_NIP04          = 0x00000004u;
        public const uint NC_ENC_VERSION_NIP44          = 0x00000002c;

        public const uint NC_ENC_SET_VERSION            = 0x01u;
        public const uint NC_ENC_SET_IV                 = 0x02u;
        public const uint NC_ENC_SET_NIP44_MAC_KEY      = 0x03u;
        public const uint NC_ENC_SET_NIP04_KEY          = 0x04u;

        public const NCResult NC_SUCCESS                = 0x00;

        public enum NCErrorCodes : long
        {
            NC_SUCCESS                  = 0,

            //Generic argument related errors
            E_NULL_PTR                  = 1,
            E_INVALID_ARG               = 2,
            E_INVALID_CTX               = 3,
            E_ARGUMENT_OUT_OF_RANGE     = 4,
            E_OPERATION_FAILED          = 5,
            E_VERSION_NOT_SUPPORTED     = 6,

            //Cipher errors
            E_CIPHER_INVALID_FORMAT     = 11,
            E_CIPHER_BAD_NONCE          = 12,
            E_CIPHER_MAC_INVALID        = 13,
            E_CIPHER_NO_OUTPUT          = 14,
            E_CIPHER_BAD_INPUT          = 15,
            E_CIPHER_BAD_INPUT_SIZE     = 16
        }

        //Cipher flags
        public const uint NC_UTIL_CIPHER_MODE           = 0x01u;



        private readonly FunctionTable _functions = FunctionTable.BuildFunctionTable(Library);

        /// <summary>
        /// Gets a reference to the loaded function table for 
        /// the native library
        /// </summary>
        internal ref readonly FunctionTable Functions
        {
            get
            {
                Check();
                Library.ThrowIfClosed();
                return ref _functions;
            }
        }

        /// <summary>
        /// Gets a value that determines if the library has been released
        /// </summary>
        internal bool IsClosed => Library.IsClosed || Library.IsInvalid;

        /// <summary>
        /// Initialize a new NCContext for use. This may be done once at app startup
        /// and is thread-safe for the rest of the application lifetime.
        /// </summary>
        /// <param name="heap"></param>
        /// <param name="entropy32">Initialization entropy buffer</param>
        /// <param name="size">The size of the buffer (must be 32 bytes)</param>
        /// <returns>The inialized context</returns>
        /// <exception cref="OutOfMemoryException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public NCContext Initialize(IUnmangedHeap heap, ref readonly byte entropy32, int size)
        {
            ArgumentNullException.ThrowIfNull(heap);

            //Entropy must be exactly 32 bytes
            ArgumentOutOfRangeException.ThrowIfNotEqual(size, NC_CTX_ENTROPY_SIZE);

            //Get struct size
            nuint ctxSize = Functions.NCGetContextStructSize.Invoke();

            //Allocate the context with the struct alignment on a heap
            IntPtr ctx = heap.Alloc(1, ctxSize, true);
            try
            {
                NCResult result;
                fixed (byte* p = &entropy32)
                {
                    result = Functions.NCInitContext.Invoke(ctx, p);
                }

                NCUtil.CheckResult<FunctionTable.NCInitContextDelegate>(result, true);

                Trace.WriteLine($"Initialzied noscrypt context 0x{ctx:x}");

                return new NCContext(ctx, heap, this);
            }
            catch
            {
                heap.Free(ref ctx);
                throw;
            }
        }

        /// <summary>
        /// Initialize a new NCContext for use. This may be done once at app startup
        /// and is thread-safe for the rest of the application lifetime.
        /// </summary>
        /// <param name="heap"></param>
        /// <param name="enropy32">The 32byte random seed/nonce for the noscrypt context</param>
        /// <returns>The inialized context</returns>
        /// <exception cref="OutOfMemoryException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public NCContext Initialize(IUnmangedHeap heap, ReadOnlySpan<byte> enropy32)
        {
            return Initialize(
                heap,
                ref MemoryMarshal.GetReference(enropy32),
                enropy32.Length
            );
        }

        /// <summary>
        /// Initializes a new NostrCrypto context wraper directly that owns the internal context.
        /// This may be done once at app startup and is thread-safe for the rest of the 
        /// application lifetime. 
        /// </summary>
        /// <param name="heap">The heap to allocate the context from</param>
        /// <param name="entropy32">The random entropy data to initialize the context with</param>
        /// <returns>The library wrapper handle</returns>
        public NostrCrypto InitializeCrypto(IUnmangedHeap heap, ReadOnlySpan<byte> entropy32)
        {
            ArgumentNullException.ThrowIfNull(heap);

            //Create the crypto interface from the new context object
            return new NostrCrypto(
                context: Initialize(heap, entropy32), 
                ownsContext: true
            );
        }

        /// <summary>
        /// Initializes a new NostrCrypto context wraper directly that owns the internal context.
        /// This may be done once at app startup and is thread-safe for the rest of the 
        /// application lifetime. 
        /// </summary>
        /// <param name="heap">The heap to allocate the context from</param>
        /// <param name="random">Random source used to generate context entropy</param>
        /// <returns>The library wrapper handle</returns>
        public NostrCrypto InitializeCrypto(IUnmangedHeap heap, IRandomSource random)
        {
            ArgumentNullException.ThrowIfNull(random);

            //Get random bytes for context entropy
            Span<byte> entropy = stackalloc byte[NC_CTX_ENTROPY_SIZE];
            random.GetRandomBytes(entropy);

            NostrCrypto nc = InitializeCrypto(heap, entropy);

            MemoryUtil.InitializeBlock(entropy);

            return nc;
        }

        ///<inheritdoc/>
        protected override void Free()
        {
            if (OwnsHandle)
            {
                Library.Dispose();
                Trace.WriteLine($"Disposed noscrypt library 0x{Library.DangerousGetHandle():x}");
            }
        }

        /// <summary>
        /// Loads the native library from the specified path and initializes the 
        /// function table for use.
        /// </summary>
        /// <param name="path">The native library path or name to load</param>
        /// <param name="search">The search path options</param>
        /// <returns>The loaded library instance</returns>
        /// <exception cref="DllNotFoundException"></exception>
        public static NoscryptLibrary Load(string path, DllImportSearchPath search)
        {
            //Load the native library
            SafeLibraryHandle handle = SafeLibraryHandle.LoadLibrary(path, search);

            Trace.WriteLine($"Loaded noscrypt library 0x{handle.DangerousGetHandle():x} from {path}");

            //Create the wrapper
            return new NoscryptLibrary(handle, true);
        }

        /// <summary>
        /// Loads the native library from the specified path and initializes the 
        /// function table for use.
        /// </summary>
        /// <param name="path">The native library path or name to load</param>
        /// <returns>The loaded library instance</returns>
        /// <exception cref="DllNotFoundException"></exception>
        public static NoscryptLibrary Load(string path) => Load(path, DllImportSearchPath.SafeDirectories);

        /// <summary>
        /// Attempts to load the default noscrypt library from the system search path
        /// </summary>
        /// <returns>The loaded library instance</returns>
        /// <exception cref="DllNotFoundException"></exception>
        public static NoscryptLibrary LoadDefault() => Load(NoscryptDefaultLibraryName, DllImportSearchPath.SafeDirectories);
    }  
}
