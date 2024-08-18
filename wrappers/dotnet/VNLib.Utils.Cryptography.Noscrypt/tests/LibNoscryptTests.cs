using Microsoft.VisualStudio.TestTools.UnitTesting;

using System;
using System.Text;
using System.Text.Json;

using VNLib.Hashing;
using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Utils.Cryptography.Noscrypt.Encryption;
using VNLib.Utils.Cryptography.Noscrypt.Random;

namespace VNLib.Utils.Cryptography.Noscrypt.Tests
{
    [TestClass()]
    public class LibNoscryptTests : IDisposable
    {

        const string NoscryptLibWinDebug = @"../../../../../../../build/windows/Debug/noscrypt.dll";


        //Keys generated using npx noskey package
        const string TestPrivateKeyHex = "98c642360e7163a66cee5d9a842b252345b6f3f3e21bd3b7635d5e6c20c7ea36";
        const string TestPublicKeyHex = "0db15182c4ad3418b4fbab75304be7ade9cfa430a21c1c5320c9298f54ea5406";

        const string TestPrivateKeyHex2 = "3032cb8da355f9e72c9a94bbabae80ca99d3a38de1aed094b432a9fe3432e1f2";
        const string TestPublicKeyHex2 = "421181660af5d39eb95e48a0a66c41ae393ba94ffeca94703ef81afbed724e5a";

        const string Nip44VectorTestFile = "nip44.vectors.json";

#nullable disable
        private NoscryptLibrary _testLib;
        private JsonDocument _testVectors;
#nullable enable

        [TestInitialize]
        public void Initialize()
        {
            _testLib = NoscryptLibrary.Load(NoscryptLibWinDebug);
            _testVectors = JsonDocument.Parse(File.ReadAllText(Nip44VectorTestFile));
        }


        [TestMethod()]
        public void InitializeTest()
        {
            //Random context seed
            ReadOnlySpan<byte> seed = RandomHash.GetRandomBytes(32);

            //Init new context and interface
            NCContext context = _testLib.Initialize(MemoryUtil.Shared, seed);

            using NostrCrypto crypto = new(context, true);
        }

        [TestMethod()]
        public void ValidateSecretKeyTest()
        {
            //Random context seed
            ReadOnlySpan<byte> seed = RandomHash.GetRandomBytes(32);
            ReadOnlySpan<byte> secretKey = RandomHash.GetRandomBytes(32);
            Span<byte> publicKey = stackalloc byte[32];

            using NostrCrypto crypto = _testLib.InitializeCrypto(MemoryUtil.Shared, seed);

            //validate the secret key
            Assert.IsTrue(crypto.ValidateSecretKey(in NCUtil.AsSecretKey(secretKey)));

            //Generate the public key
            crypto.GetPublicKey(
                in NCUtil.AsSecretKey(secretKey),
                ref NCUtil.AsPublicKey(publicKey)
            );

            //Make sure the does not contain all zeros
            Assert.IsTrue(publicKey.ToArray().Any(b => b != 0));
        }

        [TestMethod()]
        public void TestGetPublicKey()
        {
            //Random context seed
            ReadOnlySpan<byte> seed = RandomHash.GetRandomBytes(32);

            using NostrCrypto crypto = _testLib.InitializeCrypto(MemoryUtil.Shared, seed);

            //Test known key 1
            TestKnownKeys(
                crypto,
                Convert.FromHexString(TestPrivateKeyHex),
                Convert.FromHexString(TestPublicKeyHex)
            );

            //Test known key 2
            TestKnownKeys(
                crypto,
                Convert.FromHexString(TestPrivateKeyHex2),
                Convert.FromHexString(TestPublicKeyHex2)
            );


            static void TestKnownKeys(NostrCrypto lib, ReadOnlySpan<byte> knownSec, ReadOnlySpan<byte> kownPub)
            {
                NCPublicKey pubKey;

                //Invoke test function
                lib.GetPublicKey(
                    in NCUtil.AsSecretKey(knownSec),
                    ref pubKey
                );

                //Make sure known key matches the generated key
                Assert.IsTrue(pubKey.AsSpan().SequenceEqual(kownPub));
            }
        }

        //Test argument validations
        [TestMethod()]
        public void TestPublicApiArgValidations()
        {
            //Random context seed
            ReadOnlySpan<byte> seed = RandomHash.GetRandomBytes(32);

            using NostrCrypto crypto = _testLib.InitializeCrypto(MemoryUtil.Shared, seed);

            NCSecretKey secKey = default;
            NCPublicKey pubKey = default;

            //noThrow (its a bad sec key but it should not throw)
            crypto.ValidateSecretKey(ref secKey);
            Assert.ThrowsException<ArgumentNullException>(() => crypto.ValidateSecretKey(ref NCSecretKey.NullRef));

            //public key
            Assert.ThrowsException<ArgumentNullException>(() => crypto.GetPublicKey(ref NCSecretKey.NullRef, ref pubKey));
            Assert.ThrowsException<ArgumentNullException>(() => crypto.GetPublicKey(in secKey, ref NCPublicKey.NullRef));
        }

        [TestMethod()]
        public void CorrectEncryptionTest()
        {
            using NostrCrypto nc = _testLib.InitializeCrypto(MemoryUtil.Shared, RandomHash.GetRandomBytes(32));

            using NoscryptCipher cipher = nc.AllocCipher(NoscryptCipherVersion.Nip44, NoscryptCipherFlags.EncryptDefault);

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
                nc.GetPublicKey(in NCUtil.AsSecretKey(secKey2), ref pub2);

                //Assign existing nonce
                nonce.CopyTo(cipher.IvBuffer);

                cipher.Update(
                    in NCUtil.AsSecretKey(secKey1),
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
            using NostrCrypto nc = _testLib.InitializeCrypto(MemoryUtil.Shared, NCFallbackRandom.Shared);

            using NoscryptCipher msgCipher = nc.AllocCipher(NoscryptCipherVersion.Nip44, NoscryptCipherFlags.DecryptDefault);

            using IMemoryHandle<byte> ptBuffer = MemoryUtil.SafeAllocNearestPage(1200, false);

            foreach (EncryptionVector vector in GetEncryptionVectors())
            {
                ReadOnlySpan<byte> secKey1 = Convert.FromHexString(vector.sec1);
                ReadOnlySpan<byte> secKey2 = Convert.FromHexString(vector.sec2);
                ReadOnlySpan<byte> expectedPt = Encoding.UTF8.GetBytes(vector.plaintext);
                ReadOnlySpan<byte> message = Convert.FromBase64String(vector.payload);

                NCPublicKey pub2 = default;

                //Recover public keys
                nc.GetPublicKey(in NCUtil.AsSecretKey(secKey2), ref pub2);

                //update performs the decryption operation (mac is also verified by default)
                msgCipher.Update(
                    in NCUtil.AsSecretKey(secKey1),
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
            using NostrCrypto nc = _testLib.InitializeCrypto(MemoryUtil.Shared, RandomHash.GetRandomBytes(32));
         
            Span<byte> convKeyOut = stackalloc byte[32];

            foreach (EncryptionVector v in GetEncryptionVectors())
            {
                ReadOnlySpan<byte> secKey1 = Convert.FromHexString(v.sec1);
                ReadOnlySpan<byte> secKey2 = Convert.FromHexString(v.sec2);
                ReadOnlySpan<byte> conversationKey = Convert.FromHexString(v.conversation_key);

                NCPublicKey pubkey2 = default;
                nc.GetPublicKey(in NCUtil.AsSecretKey(secKey2), ref pubkey2);

                nc.GetConverstationKey(
                    in NCUtil.AsSecretKey(secKey1),
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
