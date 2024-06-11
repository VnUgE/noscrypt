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

namespace VNLib.Utils.Cryptography.Noscrypt
{
    public readonly ref struct Nip44Message(ReadOnlySpan<byte> payload)
    {
        readonly ReadOnlySpan<byte> _payload = payload;

        public ReadOnlySpan<byte> Payload => _payload;

        public ReadOnlySpan<byte> Nonce => Nip44Util.GetNonceFromPayload(_payload);

        public ReadOnlySpan<byte> Ciphertext => Nip44Util.GetCiphertextFromPayload(_payload);

        public ReadOnlySpan<byte> Mac => Nip44Util.GetMacFromPayload(_payload);

        public ReadOnlySpan<byte> NonceAndCiphertext => Nip44Util.GetNonceAndCiphertext(_payload);

        public byte Version => Nip44Util.GetMessageVersion(_payload);
    }
}
