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

using static VNLib.Utils.Cryptography.Noscrypt.NoscryptLibrary;

namespace VNLib.Utils.Cryptography.Noscrypt
{
    /// <summary>
    /// The NIP04 encryption version used by the Nostr protocol
    /// </summary>
    public sealed class NCNip04EncryptionVersion : INostrEncryptionVersion
    {
        /// <summary>
        /// A static nip04 encryption version instance
        /// </summary>
        public static readonly NCNip04EncryptionVersion Instance = new();

        ///<inheritdoc/>
        uint INostrEncryptionVersion.Version => NC_ENC_VERSION_NIP04;

        ///<inheritdoc/>
        int INostrEncryptionVersion.GetMessageBufferSize(int dataSize) => Nip04Util.CalcBufferSize(dataSize);

        ///<inheritdoc/>
        int INostrEncryptionVersion.GetPayloadBufferSize(int dataSize) => Nip04Util.CalcBufferSize(dataSize);        
    }

}
