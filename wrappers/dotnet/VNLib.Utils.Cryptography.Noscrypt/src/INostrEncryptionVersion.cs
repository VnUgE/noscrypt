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

namespace VNLib.Utils.Cryptography.Noscrypt
{
    /// <summary>
    /// Represents a message encryption version used by the Nostr protocol
    /// </summary>
    public interface INostrEncryptionVersion
    {
        /// <summary>
        /// The noscrypt compatible encryption version
        /// </summary>
        internal uint Version { get; }

        /// <summary>
        /// Calculates the required payload buffer size for the specified data size
        /// </summary>
        /// <param name="dataSize">The size of the input data</param>
        /// <returns>The estimated size of the buffer required to complete the opeation</returns>
        internal int GetPayloadBufferSize(int dataSize);

        /// <summary>
        /// Calculates the required message buffer size for the specified data size
        /// </summary>
        /// <param name="dataSize">Plain text data size</param>
        /// <returns>The estimated size of the buffer required to complete the opeation</returns>
        internal int GetMessageBufferSize(int dataSize);
    }

}
