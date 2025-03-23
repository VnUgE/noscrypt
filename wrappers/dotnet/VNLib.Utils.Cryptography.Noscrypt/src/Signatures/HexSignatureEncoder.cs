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

namespace VNLib.Utils.Cryptography.Noscrypt.Signatures
{
    public sealed class HexSignatureEncoder : INostrSignatureEncoder
    {
        /// <summary>
        /// Shared formatter instance for hex signatures
        /// </summary>
        public static HexSignatureEncoder Instance { get; } = new HexSignatureEncoder();

        ///<inheritdoc/>
        public string GetString(ReadOnlySpan<byte> signature) => Convert.ToHexString(signature);
    }

}
