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

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using static VNLib.Utils.Cryptography.Noscrypt.Noscrypt;

namespace VNLib.Utils.Cryptography.Noscrypt
{
    /// <summary>
    /// Represents an nostr variant of a secp265k1 secret key that matches 
    /// the size of the native library
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Size = Size)]
    public unsafe struct NCSecretKey
    {
        /// <summary>
        /// The size of the secret key in bytes
        /// </summary>
        public const int Size = NC_SEC_KEY_SIZE;

        /// <summary>
        /// Gets a null reference to a secret key
        /// </summary>
        public static ref NCSecretKey NullRef => ref Unsafe.NullRef<NCSecretKey>();

        private fixed byte key[Size];
    }
}
