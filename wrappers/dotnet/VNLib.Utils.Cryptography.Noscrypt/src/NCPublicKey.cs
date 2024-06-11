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
using System.Runtime.InteropServices;

using static VNLib.Utils.Cryptography.Noscrypt.LibNoscrypt;

namespace VNLib.Utils.Cryptography.Noscrypt
{
    /// <summary>
    /// Represents a user's secp256k1 public key for use with the Nostrcrypt library
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Size = NC_SEC_PUBKEY_SIZE)]
    public unsafe struct NCPublicKey
    {
        private fixed byte key[NC_SEC_PUBKEY_SIZE];
    }
}
