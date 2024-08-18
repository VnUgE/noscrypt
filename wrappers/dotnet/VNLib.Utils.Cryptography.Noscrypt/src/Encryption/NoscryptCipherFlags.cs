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

namespace VNLib.Utils.Cryptography.Noscrypt.Encryption
{
    /// <summary>
    /// Cipher specific flags that control the behavior of a cipher 
    /// instance
    /// </summary>
    [Flags]
    public enum NoscryptCipherFlags : uint
    {
        /// <summary>
        /// Puts the cipher into encryption mode
        /// </summary>
        ModeEncryption = 0x00u,

        /// <summary>
        /// Puts the cipher into decryption mode
        /// </summary>
        ModeDecryption = 0x01u,

        /// <summary>
        /// Forces all internal memory to be freed when 
        /// the cipher is freed
        /// </summary>
        ZeroOnFree = 0x02u,

        /// <summary>
        /// Disables mac verification during decryption operations,
        /// by default nip44 macs are verified before the decryption
        /// operation.
        /// </summary>
        MacNoVerify = 0x04u,

        /// <summary>
        /// Allows allocated cipher instances to be reused multiple 
        /// times. Otherwise the cipher may only be used once after
        /// allocation.
        /// </summary>
        Reusable = 0x08u,

        EncryptDefault = ModeEncryption | Reusable | ZeroOnFree,
        DecryptDefault = ModeDecryption | Reusable | ZeroOnFree
    }
}
