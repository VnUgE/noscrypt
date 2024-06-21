﻿// Copyright (C) 2024 Vaughn Nugent
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

using VNLib.Hashing;

namespace VNLib.Utils.Cryptography.Noscrypt
{
    /// <summary>
    /// A fallback crypographic random source used for default
    /// rng if you wish
    /// </summary>
    public sealed class NcFallbackRandom : IRandomSource
    {
        /// <summary>
        /// Gets the shared instance of the fallback random source
        /// </summary>
        public static NcFallbackRandom Shared { get; } = new NcFallbackRandom();

        /// <inheritdoc/>
        public void GetRandomBytes(Span<byte> buffer) => RandomHash.GetRandomBytes(buffer);
    }
}
