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

using VNLib.Utils.Native;
using VNLib.Utils.Extensions;

using NCResult = System.Int64;

namespace VNLib.Utils.Cryptography.Noscrypt.@internal
{

    internal unsafe readonly struct FunctionTable
    {

        public readonly NCGetContextStructSizeDelegate NCGetContextStructSize;
        public readonly NCInitContextDelegate NCInitContext;
        public readonly NCReInitContextDelegate NCReInitContext;
        public readonly NCDestroyContextDelegate NCDestroyContext;
        public readonly NCGetPublicKeyDelegate NCGetPublicKey;
        public readonly NCValidateSecretKeyDelegate NCValidateSecretKey;
        public readonly NCSignDataDelegate NCSignData;
        public readonly NCVerifyDataDelegate NCVerifyData;
        public readonly NCUtilCipherAllocDelegate NCUtilCipherAlloc;
        public readonly NCUtilCipherFreeDelegate NCUtilCipherFree;
        public readonly NCUtilCipherInitDelegate NCUtilCipherInit;
        public readonly NCUtilCipherGetFlagsDelegate NCUtilCipherGetFlags;
        public readonly NCUtilCipherGetOutputSizeDelegate NCUtilCipherGetOutputSize;
        public readonly NCUtilCipherReadOutputDelegate NCUtilCipherReadOutput;
        public readonly NCUtilCipherSetPropertyDelegate NCUtilCipherSetProperty;
        public readonly NCUtilCipherUpdateDelegate NCUtilCipherUpdate;
        public readonly NCUtilCipherGetIvSizeDelegate NCUtilCipherGetIvSize;


#if DEBUG
        public readonly NCGetConversationKeyDelegate NCGetConversationKey;
#endif

        private FunctionTable(SafeLibraryHandle library)
        {
            //Load the required high-level api functions
            NCGetContextStructSize = library.DangerousGetFunction<NCGetContextStructSizeDelegate>();
            NCInitContext = library.DangerousGetFunction<NCInitContextDelegate>();
            NCReInitContext = library.DangerousGetFunction<NCReInitContextDelegate>();
            NCDestroyContext = library.DangerousGetFunction<NCDestroyContextDelegate>();
            NCGetPublicKey = library.DangerousGetFunction<NCGetPublicKeyDelegate>();
            NCValidateSecretKey = library.DangerousGetFunction<NCValidateSecretKeyDelegate>();
            NCSignData = library.DangerousGetFunction<NCSignDataDelegate>();
            NCVerifyData = library.DangerousGetFunction<NCVerifyDataDelegate>();
            NCSignData = library.DangerousGetFunction<NCSignDataDelegate>();
            NCVerifyData = library.DangerousGetFunction<NCVerifyDataDelegate>();
            
            //Cipher util library functions
            NCUtilCipherAlloc = library.DangerousGetFunction<NCUtilCipherAllocDelegate>();
            NCUtilCipherFree = library.DangerousGetFunction<NCUtilCipherFreeDelegate>();
            NCUtilCipherInit = library.DangerousGetFunction<NCUtilCipherInitDelegate>();
            NCUtilCipherGetFlags = library.DangerousGetFunction<NCUtilCipherGetFlagsDelegate>();
            NCUtilCipherGetOutputSize = library.DangerousGetFunction<NCUtilCipherGetOutputSizeDelegate>();
            NCUtilCipherReadOutput = library.DangerousGetFunction<NCUtilCipherReadOutputDelegate>();
            NCUtilCipherSetProperty = library.DangerousGetFunction<NCUtilCipherSetPropertyDelegate>();
            NCUtilCipherUpdate = library.DangerousGetFunction<NCUtilCipherUpdateDelegate>();
            NCUtilCipherGetIvSize = library.DangerousGetFunction<NCUtilCipherGetIvSizeDelegate>();

#if DEBUG
            NCGetConversationKey = library.DangerousGetFunction<NCGetConversationKeyDelegate>();
#endif
        }

        /// <summary>
        /// Initialize a new function table from the specified library
        /// </summary>
        /// <param name="library"></param>
        /// <returns>The function table structure</returns>
        /// <exception cref="MissingMemberException"></exception>
        /// <exception cref="EntryPointNotFoundException"></exception>
        public static FunctionTable BuildFunctionTable(SafeLibraryHandle library) => new (library);

        /*
         * ################################################
         * 
         *      Functions match the noscrypt.h header file
         * 
         * ################################################
         */

        //FUCNTIONS
        [SafeMethodName("NCGetContextStructSize")]
        internal delegate uint NCGetContextStructSizeDelegate();

        [SafeMethodName("NCInitContext")]
        internal delegate NCResult NCInitContextDelegate(IntPtr ctx, byte* entropy32);

        [SafeMethodName("NCReInitContext")]
        internal delegate NCResult NCReInitContextDelegate(IntPtr ctx, byte* entropy32);

        [SafeMethodName("NCDestroyContext")]
        internal delegate NCResult NCDestroyContextDelegate(IntPtr ctx);

        [SafeMethodName("NCGetPublicKey")]
        internal delegate NCResult NCGetPublicKeyDelegate(IntPtr ctx, NCSecretKey* secKey, NCPublicKey* publicKey);

        [SafeMethodName("NCValidateSecretKey")]
        internal delegate NCResult NCValidateSecretKeyDelegate(IntPtr ctx, NCSecretKey* secKey);

        [SafeMethodName("NCSignData")]
        internal delegate NCResult NCSignDataDelegate(IntPtr ctx, NCSecretKey* sk, byte* random32, byte* data, uint dataSize, byte* sig64);

        [SafeMethodName("NCVerifyData")]
        internal delegate NCResult NCVerifyDataDelegate(IntPtr ctx, NCPublicKey* pk, byte* data, uint dataSize, byte* sig64);

        [SafeMethodName("NCGetConversationKey")]
        internal delegate NCResult NCGetConversationKeyDelegate(IntPtr ctx, NCSecretKey* sk, NCPublicKey* pk, byte* keyOut32);


        [SafeMethodName("NCUtilCipherAlloc")]
        internal delegate IntPtr NCUtilCipherAllocDelegate(uint version, uint flags);

        [SafeMethodName("NCUtilCipherFree")]
        internal delegate void NCUtilCipherFreeDelegate(IntPtr cipher);

        [SafeMethodName("NCUtilCipherInit")]
        internal delegate NCResult NCUtilCipherInitDelegate(IntPtr cipher, byte* inputData, uint inputLen);

        [SafeMethodName("NCUtilCipherGetFlags")]
        internal delegate NCResult NCUtilCipherGetFlagsDelegate(IntPtr cipher);

        [SafeMethodName("NCUtilCipherGetOutputSize")]
        internal delegate NCResult NCUtilCipherGetOutputSizeDelegate(IntPtr cipher);

        [SafeMethodName("NCUtilCipherReadOutput")]
        internal delegate NCResult NCUtilCipherReadOutputDelegate(IntPtr cipher, byte* outputData, uint outputLen);

        [SafeMethodName("NCUtilCipherSetProperty")]
        internal delegate NCResult NCUtilCipherSetPropertyDelegate(IntPtr cipher, uint property, byte* value, uint valueLen);

        [SafeMethodName("NCUtilCipherUpdate")]
        internal delegate NCResult NCUtilCipherUpdateDelegate(IntPtr cipher, IntPtr libContext, NCSecretKey* secKey, NCPublicKey* pubKey);

        [SafeMethodName("NCUtilCipherGetIvSize")]
        internal delegate NCResult NCUtilCipherGetIvSizeDelegate(IntPtr cipher);
    }
}
