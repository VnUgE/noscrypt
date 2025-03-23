using Microsoft.VisualStudio.TestTools.UnitTesting;

using System;
using System.Text;
using System.Text.Json;

using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Utils.Cryptography.Noscrypt.Random;
using VNLib.Utils.Cryptography.Noscrypt.Encryption;

namespace VNLib.Utils.Cryptography.Noscrypt.Tests
{

    [TestClass]
    public class NoscryptVectorTests : IDisposable
    {
        const string Nip44VectorTestFile = "nip44.vectors.json";

#nullable disable
        private Noscrypt _testLib;
        private JsonDocument _testVectors;
#nullable enable

        [TestInitialize]
        public void Initialize()
        {
            _testLib = Noscrypt.LoadDefaultLibrary();
            _testVectors = JsonDocument.Parse(File.ReadAllText(Nip44VectorTestFile));
        }

        [TestMethod]
        public void CorrectEncryptionTest()
        {
            using NCContext context = _testLib.AllocContext(NCFallbackRandom.Shared);
            using NCMessageCipher cipher = NCMessageCipher.Create(context, NCCipherVersion.Nip44, NCCipherFlags.EncryptDefault);

            using IMemoryHandle<byte> ctBuffer = MemoryUtil.SafeAllocNearestPage(1200, false);

            foreach (EncryptionVector v in GetEncryptionVectors())
            {              

                ReadOnlySpan<byte> secKey1 = Convert.FromHexString(v.sec1);
                ReadOnlySpan<byte> secKey2 = Convert.FromHexString(v.sec2);
                ReadOnlySpan<byte> plainText = Encoding.UTF8.GetBytes(v.plaintext);
                ReadOnlySpan<byte> nonce = Convert.FromHexString(v.nonce);
                ReadOnlySpan<byte> message = Convert.FromBase64String(v.payload);
              
                NCPublicKey pub2;

                //Recover public keys
                NCKeyUtil.GetPublicKey(context, in NCKeyUtil.AsSecretKey(secKey2), ref pub2);

                //Assign existing nonce
                nonce.CopyTo(cipher.IvBuffer);

                cipher.Update(
                    in NCKeyUtil.AsSecretKey(secKey1),
                    in pub2,
                    plainText
                );

                Span<byte> outputBuffer = ctBuffer.AsSpan(0, cipher.GetOutputSize());

                Assert.AreEqual<int>(cipher.ReadOutput(outputBuffer), message.Length);

                //Make sure the cipher text matches the expected payload
                if (!outputBuffer.SequenceEqual(message))
                {
                    Console.WriteLine($"Input data: {v.plaintext}");
                    Console.WriteLine($" \n{Convert.ToHexString(outputBuffer)}\n{Convert.ToHexString(message)}");
                    Assert.Fail($"Cipher text does not match expected message");
                }
            }
        }

        [TestMethod]
        public void CorrectDecryptionTest()
        {
            using NCContext context = _testLib.AllocContext(NCFallbackRandom.Shared);
            using NCMessageCipher msgCipher = NCMessageCipher.Create(context, NCCipherVersion.Nip44, NCCipherFlags.DecryptDefault);

            using IMemoryHandle<byte> ptBuffer = MemoryUtil.SafeAllocNearestPage(1200, false);

            foreach (EncryptionVector vector in GetEncryptionVectors())
            {
                ReadOnlySpan<byte> secKey1 = Convert.FromHexString(vector.sec1);
                ReadOnlySpan<byte> secKey2 = Convert.FromHexString(vector.sec2);
                ReadOnlySpan<byte> expectedPt = Encoding.UTF8.GetBytes(vector.plaintext);
                ReadOnlySpan<byte> message = Convert.FromBase64String(vector.payload);

                NCPublicKey pub2 = default;

                //Recover public keys
                NCKeyUtil.GetPublicKey(context, in NCKeyUtil.AsSecretKey(secKey2), ref pub2);

                //update performs the decryption operation (mac is also verified by default)
                msgCipher.Update(
                    in NCKeyUtil.AsSecretKey(secKey1),
                    in pub2,
                    message
                );

                int outLen = msgCipher.GetOutputSize();
                Assert.IsTrue(outLen == expectedPt.Length);

                Span<byte> plaintext = ptBuffer.AsSpan(0, outLen);

                msgCipher.ReadOutput(plaintext);

                if (!plaintext.SequenceEqual(expectedPt))
                {
                    Console.WriteLine($"Input data: {vector.plaintext}");
                    Console.WriteLine($" \n{Convert.ToHexString(plaintext)}\n{Convert.ToHexString(expectedPt)}");
                    Assert.Fail("Decrypted data does not match expected plaintext");
                }
            }
        }


        [TestMethod]
        public void InvalidPlaintextSizes()
        {
            using NCContext context = _testLib.AllocContext(NCFallbackRandom.Shared);
            using NCMessageCipher msgCipher = NCMessageCipher.Create(context, NCCipherVersion.Nip44, NCCipherFlags.EncryptDefault);

            NCPublicKey pubkey;
            NCSecretKey secKey;
            byte testByte = 0;

            NCFallbackRandom.Shared.GetRandomBytes(NCKeyUtil.AsSpan(ref secKey));
            NCKeyUtil.GetPublicKey(context, in secKey, ref pubkey);
            msgCipher.SetRandomIv(NCFallbackRandom.Shared);

            //update performs the decryption operation (mac is also verified by default)
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => msgCipher.Update(in secKey, in pubkey, in testByte, 0));

            //Should be fine
            msgCipher.Update(in secKey, in pubkey, in testByte, 1);

            /*
             *  65536 is too large of a plaintext message and should fail before 
             *  the pointer is dereferences/read from. Otherwise this will probably 
             *  cause a segfault.
             */
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => msgCipher.Update(in secKey, in pubkey, in testByte, 65536));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => msgCipher.Update(in secKey, in pubkey, in testByte, 100000));
        }


        //Converstation key is only defined in debug builds
#if DEBUG

        [TestMethod]
        public void ConverstationKeyTest()
        {
            using NCContext context = _testLib.AllocContext(NCFallbackRandom.Shared);

            Span<byte> convKeyOut = stackalloc byte[32];

            foreach (EncryptionVector v in GetEncryptionVectors())
            {
                ReadOnlySpan<byte> secKey1 = Convert.FromHexString(v.sec1);
                ReadOnlySpan<byte> secKey2 = Convert.FromHexString(v.sec2);
                ReadOnlySpan<byte> conversationKey = Convert.FromHexString(v.conversation_key);

                NCPublicKey pubkey2 = default;
                NCKeyUtil.GetPublicKey(context, in NCKeyUtil.AsSecretKey(secKey2), ref pubkey2);

                NCCipherUtil.GetConverstationKey(
                    context, 
                    in NCKeyUtil.AsSecretKey(secKey1), 
                    in pubkey2, 
                    convKeyOut
                );

                Assert.IsTrue(conversationKey.SequenceEqual(convKeyOut));

                MemoryUtil.InitializeBlock(convKeyOut);
            }
        }
#endif

        [TestMethod]
        public void PaddingTest()
        {
            using NCContext context = _testLib.AllocContext(NCFallbackRandom.Shared);

            foreach (uint[] vector in GetPaddingVectors())
            {
                uint inputSize = vector[0];
                uint desiredPaddingSize = vector[1];

                uint actualSize = NCCipherUtil.GetPaddedSize(context, NCCipherVersion.Nip44, inputSize);

                Assert.AreEqual<uint>(desiredPaddingSize, actualSize);
            }
        }

        private EncryptionVector[] GetEncryptionVectors()
        {
            return _testVectors.RootElement.GetProperty("v2")
                .GetProperty("valid")
                .GetProperty("encrypt_decrypt")
                .EnumerateArray()
                .Select(v => v.Deserialize<EncryptionVector>()!)
                .ToArray();
        }

        private uint[][] GetPaddingVectors()
        {
            return _testVectors.RootElement.GetProperty("v2")
                .GetProperty("valid")
                .GetProperty("calc_padded_len")
                .EnumerateArray()
                .Select(v => v.Deserialize<uint[]>()!)
                .ToArray();
        }

        private InvalidDecryptVector[] GetInvalidDecryptVectors()
        {
            return _testVectors.RootElement.GetProperty("v2")
                .GetProperty("invalid")
                .GetProperty("decrypt")
                .EnumerateArray()
                .Select(v => v.Deserialize<InvalidDecryptVector>()!)
                .ToArray();
        }

        void IDisposable.Dispose()
        {
            _testLib.Dispose();
            _testVectors.Dispose();
            GC.SuppressFinalize(this);
        }

        private sealed class EncryptionVector
        {
            public required string sec1 { get; set; }

            public required string sec2 { get; set; }

            public required string nonce { get; set; }

            public required string plaintext { get; set; }

            public required string payload { get; set; }

            public required string conversation_key { get; set; }
        }

        private sealed class InvalidDecryptVector
        {
            public required string conversation_key { get; set; }
            
            public required string plaintext { get; set; }

            public required string payload { get; set; }

            public required string nonce { get; set; }

            public required string note { get; set; }
        }

    }
}
