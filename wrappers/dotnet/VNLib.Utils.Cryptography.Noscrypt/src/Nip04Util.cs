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
using System.Buffers.Text;

using VNLib.Utils.Extensions;

namespace VNLib.Utils.Cryptography.Noscrypt
{
    public static class Nip04Util
    {
        public static bool IsValidPayload(ReadOnlySpan<char> payload)
        {
            /* Iv is base64 encoded so it should be 33% larger than 16 byte iv */
            ReadOnlySpan<char> iv = payload.SliceAfterParam("?iv=");
            return iv.Length > 20 && iv.Length <= 26;
        }

        public static ReadOnlySpan<char> GetIV(ReadOnlySpan<char> payload) => payload.SliceAfterParam("?iv=");

        public static ReadOnlySpan<char> GetCipherText(ReadOnlySpan<char> payload) => payload.SliceBeforeParam("?iv=");

        public static int CalcBufferSize(int dataSize)
        {
            throw new NotImplementedException();
        }

        static readonly int MaxEncodedIvLength = Base64.GetMaxEncodedToUtf8Length(16);

        public static int CalcMessageBufferSize(int dataSize)
        {
            int bufSize = CalcBufferSize(dataSize);
            return bufSize + "?iv=".Length + MaxEncodedIvLength;
        }
    }

}
