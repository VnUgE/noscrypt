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
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using static VNLib.Utils.Cryptography.Noscrypt.Noscrypt;

namespace VNLib.Utils.Cryptography.Noscrypt
{
    /// <summary>
    /// Represents a user's secp256k1 public key for use with the Nostrcrypt library
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Size = Size)]
    public unsafe struct NCPublicKey
    {
        /// <summary>
        /// The size of the public key in bytes
        /// </summary>
        public const int Size = NC_SEC_PUBKEY_SIZE;

        /// <summary>
        /// Gets a null <see cref="NCPublicKey"/> reference.
        /// </summary>
        public static ref NCPublicKey NullRef => ref Unsafe.NullRef<NCPublicKey>();

        private fixed byte key[Size];
    }
}
