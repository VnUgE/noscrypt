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

using static VNLib.Utils.Cryptography.Noscrypt.LibNoscrypt;

namespace VNLib.Utils.Cryptography.Noscrypt
{
    /// <summary>
    /// The NIP44 encryption version used by the Nostr protocol
    /// </summary>
    public sealed class NCNip44EncryptionVersion : IEncryptionVersion
    {
        /// <summary>
        /// A static nip44 encryption version instance
        /// </summary>
        public static readonly NCNip44EncryptionVersion Instance = new();

        ///<inheritdoc/>
        uint IEncryptionVersion.Version => NC_ENC_VERSION_NIP44;

        ///<inheritdoc/>
        int IEncryptionVersion.CalcBufferSize(int dataSize) => Nip44Util.CalcBufferSize(dataSize);
    }

}
