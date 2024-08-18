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
using System.Runtime.CompilerServices;
using System.Diagnostics.CodeAnalysis;

using VNLib.Utils.Cryptography.Noscrypt.@internal;
using VNLib.Utils.Cryptography.Noscrypt.Encryption;
using static VNLib.Utils.Cryptography.Noscrypt.NoscryptLibrary;

using NCResult = System.Int64;

namespace VNLib.Utils.Cryptography.Noscrypt
{
    /// <summary>
    /// A default implementation of the <see cref="INostrCrypto"/> interface
    /// </summary>
    /// <param name="context">The initialized library context</param>
    public unsafe class NostrCrypto(NCContext context, bool ownsContext) : VnDisposeable, INostrCrypto
    {
        /// <summary>
        /// Gets the underlying library context.
        /// </summary>
        public NCContext Context => context;

        private ref readonly FunctionTable Functions => ref context.Library.Functions;

        ///<inheritdoc/>
        public NoscryptCipher AllocCipher(NoscryptCipherVersion version, NoscryptCipherFlags flags) => new (context, version, flags);

        ///<inheritdoc/>
        public void GetPublicKey(ref readonly NCSecretKey secretKey, ref NCPublicKey publicKey)
        {
            Check();

            fixed (NCSecretKey* pSecKey = &secretKey)
            fixed (NCPublicKey* pPubKey = &publicKey)
            {
                NCResult result = Functions.NCGetPublicKey.Invoke(context.DangerousGetHandle(), pSecKey, pPubKey);
                NCUtil.CheckResult<FunctionTable.NCGetPublicKeyDelegate>(result, true);
            }
        }

        ///<inheritdoc/>
        public void SignData(
            ref readonly NCSecretKey secretKey, 
            ref readonly byte random32, 
            ref readonly byte data,
            uint dataSize, 
            ref byte sig64
        )
        {
            Check();
       
            fixed (NCSecretKey* pSecKey = &secretKey)
            fixed (byte* pData = &data, pSig = &sig64, pRandom = &random32)
            {
                NCResult result = Functions.NCSignData.Invoke(
                    ctx: context.DangerousGetHandle(), 
                    sk: pSecKey, 
                    random32: pRandom, 
                    data: pData, 
                    dataSize, 
                    sig64: pSig
                );

                NCUtil.CheckResult<FunctionTable.NCSignDataDelegate>(result, true);
            }
        }

        ///<inheritdoc/>
        public bool ValidateSecretKey(ref readonly NCSecretKey secretKey)
        {
            Check();

            IntPtr libCtx = context.DangerousGetHandle();

            fixed (NCSecretKey* pSecKey = &secretKey)
            {
                /*
                 * Validate should return a result of 1 if the secret key is valid
                 * or a 0 if it is not.
                 */
                NCResult result = Functions.NCValidateSecretKey.Invoke(libCtx, pSecKey);
                NCUtil.CheckResult<FunctionTable.NCValidateSecretKeyDelegate>(result, false);

                return result == NC_SUCCESS;
            }
        }

        ///<inheritdoc/>
        public bool VerifyData(
            ref readonly NCPublicKey pubKey, 
            ref readonly byte data,
            uint dataSize, 
            ref readonly byte sig64
        )
        {
            Check();
            
            fixed(NCPublicKey* pPubKey = &pubKey)
            fixed (byte* pData = &data, pSig = &sig64)
            {
                NCResult result = Functions.NCVerifyData.Invoke(context.DangerousGetHandle(), pPubKey, pData, dataSize, pSig);
                NCUtil.CheckResult<FunctionTable.NCVerifyDataDelegate>(result, false);

                return result == NC_SUCCESS;
            }
        }

#if DEBUG

        /// <summary>
        /// DEBUG ONLY: Gets the conversation key for the supplied secret key and public key
        /// </summary>
        /// <param name="secretKey">The sender's private key</param>
        /// <param name="publicKey">The receiver's public key</param>
        /// <param name="key32">A pointer to the 32byte buffer to write the conversation key to</param>
        public void GetConverstationKey(
            ref readonly NCSecretKey secretKey,
            ref readonly NCPublicKey publicKey,
            ref byte key32
        )
        {
            Check();

            fixed (NCSecretKey* pSecKey = &secretKey)
            fixed (NCPublicKey* pPubKey = &publicKey)
            fixed (byte* pKey = &key32)
            {
                NCResult result = Functions.NCGetConversationKey.Invoke(context.DangerousGetHandle(), pSecKey, pPubKey, pKey);
                NCUtil.CheckResult<FunctionTable.NCGetConversationKeyDelegate>(result, true);
            }
        }

#endif
        ///<inheritdoc/>
        protected override void Free()
        {
            if(ownsContext)
            {
                context.Dispose();
            }
        }
        
        private static void ThrowIfNullRef([DoesNotReturnIf(false)] ref readonly byte value, string name)
        {
            if(Unsafe.IsNullRef(in value))
            {
                throw new ArgumentNullException(name);
            }
        }
    }
}
