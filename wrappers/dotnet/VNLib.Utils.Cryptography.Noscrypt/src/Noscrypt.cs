// Copyright (C) 2025 Vaughn Nugent
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
    /// The ultimate wrapper for the noscrypt native library that provides
    /// access to the low-level functions and utilities provided by the library.
    /// </summary>
    /// <param name="Library">An existing noscrypt library handle</param>
    /// <param name="OwnsHandle">A value that indicates if the instance owns the library handle</param>
    public unsafe sealed class Noscrypt(SafeLibraryHandle Library, bool OwnsHandle) : VnDisposeable
    {
        public const string NoscryptDefaultLibraryName = "noscrypt";
        public const string NoscryptDllPathEnvName = "NOSCRYPT_DLL_PATH";

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
        public NCContext AllocContext(ref readonly byte entropy32, int size, IUnmangedHeap? heap = null)
        {
            heap ??= MemoryUtil.Shared;

            //Entropy must be exactly 32 bytes
            ArgumentOutOfRangeException.ThrowIfNotEqual(size, NC_CTX_ENTROPY_SIZE);

            //Allocate the context with the struct alignment on a heap
            IntPtr ctx = heap.Alloc(1, GetContextSize(), zero: true);
            try
            {
                NCResult result;
                fixed (byte* p = &entropy32)
                {
                    result = Functions.NCInitContext.Invoke(ctx, p);
                }

                NCUtil.CheckResult<FunctionTable.NCInitContextDelegate>(result, raiseOnFailure: true);

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
        public NCContext AllocContext(ReadOnlySpan<byte> enropy32, IUnmangedHeap? heap = null)
        {
            return AllocContext(
                ref MemoryMarshal.GetReference(enropy32),
                enropy32.Length,
                heap
            );
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
        public NCContext AllocContext(IRandomSource random, IUnmangedHeap? heap = null)
        {
            ArgumentNullException.ThrowIfNull(random);

            using UnsafeMemoryHandle<byte> entropyBuffer = (heap ?? MemoryUtil.Shared)
                .UnsafeAlloc<byte>(NC_CTX_ENTROPY_SIZE, zero: true);
          
            random.GetRandomBytes(entropyBuffer.Span);

            return AllocContext(entropyBuffer.Span, heap);
        }

        /// <summary>
        /// Reinitializes the context with the specified entropy
        /// </summary>
        /// <remarks>
        /// This function is not thread-safe and should not be called concurrently
        /// with other functions that rely on the context.
        /// </remarks>
        /// <param name="entropy">The randomness buffer used to randomize the context</param>
        /// <param name="size">The random data buffer size (must be equal to <see cref="NC_CTX_ENTROPY_SIZE"/>)</param>
        public unsafe void ReinitalizeContext(NCContext context, ref readonly byte entropy, int size)
        {
            ArgumentNullException.ThrowIfNull(context);

            //Entropy must be exactly 32 bytes
            ArgumentOutOfRangeException.ThrowIfNotEqual(size, NC_CTX_ENTROPY_SIZE);

            context.ThrowIfClosed();
            fixed (byte* pEntropy = &entropy)
            {                
                NCResult result = Functions.NCReInitContext.Invoke(
                    context.DangerousGetHandle(), 
                    pEntropy
                );
                
                NCUtil.CheckResult<FunctionTable.NCReInitContextDelegate>(result, raiseOnFailure: true);
            }
        }

        /// <summary>
        /// Reinitializes the context with the specified entropy
        /// </summary>
        /// <remarks>
        /// This function is not thread-safe and should not be called concurrently
        /// with other functions that rely on the context.
        /// </remarks>
        /// <param name="context">The context to reinitialize</param>
        /// <param name="entropy">The randomness buffer used to randomize the context</param>
        public void ReinitalizeContext(NCContext context, ReadOnlySpan<byte> entropy)
        {
            ReinitalizeContext(
                context, 
                in MemoryMarshal.GetReference(entropy), 
                entropy.Length
            );
        }

        /// <summary>
        /// Reinitializes the context with the specified entropy
        /// </summary>
        /// <remarks>
        /// This function is not thread-safe and should not be called concurrently
        /// with other functions that rely on the context.
        /// </remarks>
        /// <param name="context">The context to reinitialize</param>
        /// <param name="random">The random source to use to generate the new context entropy</param>
        public void ReinitalizeContext(NCContext context, IRandomSource random)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(random);

            // Allocate a buffer for the entropy from the context's heap
            using UnsafeMemoryHandle<byte> entropy = context.Heap.UnsafeAlloc<byte>(NC_CTX_ENTROPY_SIZE, zero: true);

            random.GetRandomBytes(entropy.Span);

            ReinitalizeContext(
                context,
                in entropy.GetReference(),
                entropy.IntLength
            );

            // Clear the buffer
            MemoryUtil.InitializeBlock(
                ref entropy.GetReference(),
                entropy.IntLength
            );
        }

        /// <summary>
        /// Gets the size of the context structure in bytes defined by the 
        /// library
        /// </summary>
        /// <returns>The size of the noscrypt context structure in bytes</returns>
        private uint GetContextSize() => Functions.NCGetContextStructSize.Invoke();

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
        public static Noscrypt LoadLibrary(string path, DllImportSearchPath search)
        {
            //Load the native library
            SafeLibraryHandle handle = SafeLibraryHandle.LoadLibrary(path, search);

            Trace.WriteLine($"Loaded noscrypt library 0x{handle.DangerousGetHandle():x} from {path}");

            //Create the wrapper
            return new Noscrypt(handle, true);
        }

        /// <summary>
        /// Loads the native library from the specified path and initializes the 
        /// function table for use.
        /// </summary>
        /// <param name="path">The native library path or name to load</param>
        /// <returns>The loaded library instance</returns>
        /// <exception cref="DllNotFoundException"></exception>
        public static Noscrypt LoadLibrary(string path) => LoadLibrary(path, DllImportSearchPath.SafeDirectories);

        /// <summary>
        /// Attempts to load the default noscrypt library from the system search path
        /// </summary>
        /// <returns>The loaded library instance</returns>
        /// <exception cref="DllNotFoundException"></exception>
        public static Noscrypt LoadDefaultLibrary()
        {
            string? libPath = Environment.GetEnvironmentVariable(NoscryptDllPathEnvName);
            libPath ??= NoscryptDefaultLibraryName;

            Console.WriteLine("Loading library {0}", libPath);

            libPath = libPath.Replace("\"", "");

            return LoadLibrary(libPath);
        }
    }  
}
