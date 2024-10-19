using Microsoft.VisualStudio.TestTools.UnitTesting;

using System;
using System.Text;
using System.Text.Json;
using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Utils.Cryptography.Noscrypt.Encryption;
using VNLib.Utils.Cryptography.Noscrypt.Random;

namespace VNLib.Utils.Cryptography.Noscrypt.Tests
{

    [TestClass()]
    public class NoscryptVectorTests : IDisposable
    {
        const string Nip44VectorTestFile = "nip44.vectors.json";

#nullable disable
        private NoscryptLibrary _testLib;
        private JsonDocument _testVectors;
#nullable enable

        [TestInitialize]
        public void Initialize()
        {
            _testLib = NoscryptLibrary.LoadDefault();
            _testVectors = JsonDocument.Parse(File.ReadAllText(Nip44VectorTestFile));
        }

        [TestMethod()]
        public void CorrectEncryptionTest()
        {
            using NCContext context = _testLib.Initialize(MemoryUtil.Shared, NCFallbackRandom.Shared);
            using NoscryptMessageCipher cipher = NoscryptMessageCipher.Create(context, NoscryptCipherVersion.Nip44, NoscryptCipherFlags.EncryptDefault);

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

        [TestMethod()]
        public void CorrectDecryptionTest()
        {
            using NCContext context = _testLib.Initialize(MemoryUtil.Shared, NCFallbackRandom.Shared);
            using NoscryptMessageCipher msgCipher = NoscryptMessageCipher.Create(context, NoscryptCipherVersion.Nip44, NoscryptCipherFlags.DecryptDefault);

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


        //Converstation key is only available in debug builds
#if DEBUG

        [TestMethod()]
        public void ConverstationKeyTest()
        {
            using NCContext context = _testLib.Initialize(MemoryUtil.Shared, NCFallbackRandom.Shared);

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

        private EncryptionVector[] GetEncryptionVectors()
        {
            return _testVectors.RootElement.GetProperty("v2")
                .GetProperty("valid")
                .GetProperty("encrypt_decrypt")
                .EnumerateArray()
                .Select(v => v.Deserialize<EncryptionVector>()!)
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
            public string sec1 { get; set; } = string.Empty;

            public string sec2 { get; set; } = string.Empty;

            public string nonce { get; set; } = string.Empty;

            public string plaintext { get; set; } = string.Empty;

            public string payload { get; set; } = string.Empty;

            public string conversation_key { get; set; } = string.Empty;
        }
    }
}
