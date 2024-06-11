using Microsoft.VisualStudio.TestTools.UnitTesting;

using System;
using System.Text;
using System.Text.Json;
using System.Runtime.CompilerServices;

using VNLib.Hashing;
using VNLib.Utils.Memory;

namespace VNLib.Utils.Cryptography.Noscrypt.Tests
{
    [TestClass()]
    public class LibNoscryptTests : IDisposable
    {

        const string NoscryptLibWinDebug = @"../../../../../../../out/build/x64-debug/noscrypt.dll";


        //Keys generated using npx noskey package
        const string TestPrivateKeyHex = "98c642360e7163a66cee5d9a842b252345b6f3f3e21bd3b7635d5e6c20c7ea36";
        const string TestPublicKeyHex = "0db15182c4ad3418b4fbab75304be7ade9cfa430a21c1c5320c9298f54ea5406";

        const string TestPrivateKeyHex2 = "3032cb8da355f9e72c9a94bbabae80ca99d3a38de1aed094b432a9fe3432e1f2";
        const string TestPublicKeyHex2 = "421181660af5d39eb95e48a0a66c41ae393ba94ffeca94703ef81afbed724e5a";

        const string Nip44VectorTestFile = "nip44.vectors.json";

#nullable disable
        private LibNoscrypt _testLib;
        private JsonDocument _testVectors;
#nullable enable

        [TestInitialize]
        public void Initialize()
        {
            _testLib = LibNoscrypt.Load(NoscryptLibWinDebug);
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
            Assert.ThrowsException<ArgumentNullException>(() => crypto.ValidateSecretKey(ref Unsafe.NullRef<NCSecretKey>()));

            //public key
            Assert.ThrowsException<ArgumentNullException>(() => crypto.GetPublicKey(ref Unsafe.NullRef<NCSecretKey>(), ref pubKey));
            Assert.ThrowsException<ArgumentNullException>(() => crypto.GetPublicKey(in secKey, ref Unsafe.NullRef<NCPublicKey>()));
        }

        [TestMethod()]
        public void CalcPaddedLenTest()
        {
            //Get valid padding test vectors
            (int, int)[] paddedSizes = _testVectors.RootElement.GetProperty("v2")
                .GetProperty("valid")
                .GetProperty("calc_padded_len")
                .EnumerateArray()
                .Select(v =>
                {
                    int[] testVals = v.Deserialize<int[]>()!;
                    return (testVals[0], testVals[1]);
                }).ToArray();


            foreach ((int len, int paddedLen) in paddedSizes)
            {
                Assert.AreEqual<int>(paddedLen, Nip44Util.CalcBufferSize(len) - 2);
            }
        }

        [TestMethod()]
        public void CorrectEncryptionTest()
        {
            using NostrCrypto nc = _testLib.InitializeCrypto(MemoryUtil.Shared, RandomHash.GetRandomBytes(32));

            Span<byte> macOut32 = stackalloc byte[32];

            foreach (EncryptionVector v in GetEncryptionVectors())
            {
                using NostrEncryptedMessage msg = NostrEncryptedMessage.CreateNip44Cipher(nc);

                ReadOnlySpan<byte> secKey1 = Convert.FromHexString(v.sec1);
                ReadOnlySpan<byte> secKey2 = Convert.FromHexString(v.sec2);
                ReadOnlySpan<byte> plainText = Encoding.UTF8.GetBytes(v.plaintext);
                ReadOnlySpan<byte> nonce = Convert.FromHexString(v.nonce);
                ReadOnlySpan<byte> message = Convert.FromBase64String(v.payload);
                ReadOnlySpan<byte> conversationKey = Convert.FromHexString(v.conversation_key);

                Nip44Message nip44Message = new(message);

                int ptSize = msg.GetOutputBufferSize(plainText.Length);

                Assert.AreEqual<int>(nip44Message.Ciphertext.Length, ptSize);
                Assert.AreEqual<byte>(nip44Message.Version, 0x02);
                Assert.IsTrue(nonce.SequenceEqual(nip44Message.Nonce));              
              
                NCPublicKey pub2;

                //Recover public keys
                nc.GetPublicKey(in NCUtil.AsSecretKey(secKey2), ref pub2);

                Span<byte> actualCiphertext = new byte[ptSize + 32];

                msg.SetSecretKey(secKey1)
                    .SetPublicKey(in pub2)
                    .SetNonce(nonce);

                int written = msg.EncryptMessage(plainText, actualCiphertext, macOut32);

                actualCiphertext = actualCiphertext[..written];
               
                //Make sure the cipher text matches the expected payload
                if (!actualCiphertext.SequenceEqual(nip44Message.Ciphertext))
                {
                    Console.WriteLine($"Input data: {v.plaintext}");
                    Console.WriteLine($" \n{Convert.ToHexString(actualCiphertext)}\n{Convert.ToHexString(nip44Message.Ciphertext)}");
                    Assert.Fail($"Cipher text does not match expected payload");
                }
            }
        }

        [TestMethod()]
        public void ValidateMessageMacs()
        {
            using NostrCrypto nc = _testLib.InitializeCrypto(MemoryUtil.Shared, RandomHash.GetRandomBytes(32));

            foreach (EncryptionVector v in GetEncryptionVectors())
            {
                ReadOnlySpan<byte> secKey1 = Convert.FromHexString(v.sec1);
                ReadOnlySpan<byte> secKey2 = Convert.FromHexString(v.sec2);
                ReadOnlySpan<byte> message = Convert.FromBase64String(v.payload);

                Nip44Message nip44Message = new(message);
                Assert.AreEqual<byte>(nip44Message.Version, 0x02);

                NCPublicKey pub2;

                //Recover public key2
                nc.GetPublicKey(in NCUtil.AsSecretKey(secKey2), ref pub2);

                bool success = nc.VerifyMac(
                    in NCUtil.AsSecretKey(secKey1),
                    in pub2,
                    nip44Message.Nonce,
                    nip44Message.Mac,
                    nip44Message.NonceAndCiphertext
                );

                if (!success)
                {
                    Console.WriteLine($"Failed to validate MAC for message: {v.payload}");
                    Console.Write($"Mac hex value: {Convert.ToHexString(nip44Message.Mac)}");
                    Assert.Fail("Failed to validate MAC for message");
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


        [TestMethod()]
        public void CorrectDecryptionTest()
        {
            using NostrCrypto nc = _testLib.InitializeCrypto(MemoryUtil.Shared, RandomHash.GetRandomBytes(32));

            Span<byte> hmacKeyOut = stackalloc byte[LibNoscrypt.NC_HMAC_KEY_SIZE];

            foreach (EncryptionVector vector in GetEncryptionVectors())
            {               
                ReadOnlySpan<byte> secKey1 = Convert.FromHexString(vector.sec1);
                ReadOnlySpan<byte> secKey2 = Convert.FromHexString(vector.sec2);
                ReadOnlySpan<byte> expectedPt = Encoding.UTF8.GetBytes(vector.plaintext);
                ReadOnlySpan<byte> nonce = Convert.FromHexString(vector.nonce);
                ReadOnlySpan<byte> message = Convert.FromBase64String(vector.payload);

                Nip44Message nip44Message = new(message);

                Assert.IsTrue(nip44Message.Version == 0x02);
                Assert.IsTrue(nonce.SequenceEqual(nip44Message.Nonce));

                NCPublicKey pub1;

                //Recover public keys
                nc.GetPublicKey(in NCUtil.AsSecretKey(secKey1), ref pub1);
             
                Span<byte> plaintextOut = new byte[ Nip44Util.CalcBufferSize(expectedPt.Length) ];

                Assert.IsTrue(nip44Message.Ciphertext.Length == plaintextOut.Length);

                /*
                * Decrypting messages requires the public key of the sender
                * and the secret key of the receiver
                */
                nc.Decrypt(
                    in NCUtil.AsSecretKey(secKey2),
                    in pub1,
                    nip44Message.Nonce,
                    nip44Message.Ciphertext,
                    plaintextOut
                );

                ReadOnlySpan<byte> actualPt = Nip44Util.GetPlaintextMessage(plaintextOut);

                Assert.AreEqual<int>(expectedPt.Length, actualPt.Length);
                Assert.IsTrue(actualPt.SequenceEqual(expectedPt));

                MemoryUtil.InitializeBlock(hmacKeyOut);
            }
        }


        static byte[] CreateAndFormatPlaintextOutputBuffer(ReadOnlySpan<byte> plaintext)
        {
            //Compute the required plaintext buffer size
            int paddedSize = Nip44Util.CalcBufferSize(plaintext.Length);

            byte[] data = new byte[paddedSize];

            //Format the plaintext buffer
            Nip44Util.FormatBuffer(plaintext, data, true);

            return data;
        }

        static byte[] BuildMacData(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce)
        {
            byte[] macData = new byte[ciphertext.Length + nonce.Length];

            //Nonce then cipher text
            nonce.CopyTo(macData);
            ciphertext.CopyTo(macData.AsSpan(nonce.Length));

            return macData;
        }

        EncryptionVector[] GetEncryptionVectors()
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
