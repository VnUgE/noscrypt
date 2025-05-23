﻿// Copyright (C) 2025 Vaughn Nugent
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
    public sealed class NCBase64SignatureEncoder : INostrSignatureEncoder
    {
        /// <summary>
        /// Shared formatter instance for base64 signatures
        /// </summary>
        public static NCBase64SignatureEncoder Instance { get; } = new NCBase64SignatureEncoder();

        ///<inheritdoc/>
        public string GetString(ReadOnlySpan<byte> signature) => Convert.ToBase64String(signature);
    }
}
