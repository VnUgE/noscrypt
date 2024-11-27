using Microsoft.VisualStudio.TestTools.UnitTesting;

using VNLib.Hashing;
using VNLib.Utils.Memory;
using VNLib.Utils.Cryptography.Noscrypt.Random;
using VNLib.Utils.Cryptography.Noscrypt.Singatures;

namespace VNLib.Utils.Cryptography.Noscrypt.Tests
{
    [TestClass()]
    public class LibNoscryptTests : IDisposable
    {
        //Keys generated using npx noskey package
        const string TestPrivateKeyHex = "98c642360e7163a66cee5d9a842b252345b6f3f3e21bd3b7635d5e6c20c7ea36";
        const string TestPublicKeyHex = "0db15182c4ad3418b4fbab75304be7ade9cfa430a21c1c5320c9298f54ea5406";

        const string TestPrivateKeyHex2 = "3032cb8da355f9e72c9a94bbabae80ca99d3a38de1aed094b432a9fe3432e1f2";
        const string TestPublicKeyHex2 = "421181660af5d39eb95e48a0a66c41ae393ba94ffeca94703ef81afbed724e5a";

#nullable disable
        private Noscrypt _testLib;
#nullable enable

        [TestInitialize]
        public void Initialize()
        {
            _testLib = Noscrypt.LoadDefaultLibrary();
        }

        [TestMethod()]
        public void InitializeTest()
        {
            //Init new context and interface
            using NCContext context = _testLib.AllocContext(NCFallbackRandom.Shared);
        }

        [TestMethod()]
        public void ValidateSecretKeyTest()
        {
            //Random context seed
            ReadOnlySpan<byte> secretKey = RandomHash.GetRandomBytes(32);
            Span<byte> publicKey = stackalloc byte[32];

            using NCContext context = _testLib.AllocContext(NCFallbackRandom.Shared);

            //validate the secret key
            Assert.IsTrue(NCKeyUtil.ValidateSecretKey(context, secretKey));

            //Generate the public key
            NCKeyUtil.GetPublicKey(
                context,
                in NCKeyUtil.AsSecretKey(secretKey),
                ref NCKeyUtil.AsPublicKey(publicKey)
            );

            //Make sure the does not contain all zeros
            Assert.IsTrue(publicKey.ToArray().Any(b => b != 0));
        }

        [TestMethod()]
        public void TestGetPublicKey()
        {
            using NCContext context = _testLib.AllocContext(NCFallbackRandom.Shared);

            //Test known key 1
            TestKnownKeys(
                context,
                Convert.FromHexString(TestPrivateKeyHex),
                Convert.FromHexString(TestPublicKeyHex)
            );

            //Test known key 2
            TestKnownKeys(
                context,
                Convert.FromHexString(TestPrivateKeyHex2),
                Convert.FromHexString(TestPublicKeyHex2)
            );


            static void TestKnownKeys(NCContext context, ReadOnlySpan<byte> knownSec, ReadOnlySpan<byte> kownPub)
            {
                NCPublicKey pubKey;

                //Invoke test function
                NCKeyUtil.GetPublicKey(
                    context,
                    in NCKeyUtil.AsSecretKey(knownSec),
                    ref pubKey
                );

                //Make sure known key matches the generated key
                Assert.IsTrue(NCKeyUtil.AsSpan(ref pubKey).SequenceEqual(kownPub));
            }
        }

        //Test argument validations
        [TestMethod()]
        public void TestPublicApiArgValidations()
        {
            using NCContext context = _testLib.AllocContext(NCFallbackRandom.Shared);

            byte[] bin16 = new byte[16];
            byte[] bin32 = new byte[32];
            byte[] bin64 = new byte[64];
            NCSecretKey secKey = default;
            NCPublicKey pubKey = default;

            //noThrow (its a bad sec key but it should not throw)
            NCKeyUtil.ValidateSecretKey(context, in secKey);
            /*
             * The important part about this test is that, null references become null 
             * pointers and the base library guards against null pointers
             */
            Assert.ThrowsException<ArgumentNullException>(() => NCKeyUtil.ValidateSecretKey(null!, ref NCSecretKey.NullRef));
            Assert.ThrowsException<ArgumentNullException>(() => NCKeyUtil.ValidateSecretKey(context, ref NCSecretKey.NullRef));

            //public key
            Assert.ThrowsException<ArgumentNullException>(() => NCKeyUtil.GetPublicKey(null!, in secKey, ref pubKey));
            Assert.ThrowsException<ArgumentNullException>(() => NCKeyUtil.GetPublicKey(context, ref NCSecretKey.NullRef, ref pubKey));
            Assert.ThrowsException<ArgumentNullException>(() => NCKeyUtil.GetPublicKey(context, in secKey, ref NCPublicKey.NullRef));

            /*
             *       VERIFY DATA
             */
            //Null context 
            Assert.ThrowsException<ArgumentNullException>(() =>
                NCSignatureUtil.VerifyData(null!, ref pubKey, bin32, bin64)
            );

            //Null pubkey
            Assert.ThrowsException<ArgumentNullException>(() =>
                NCSignatureUtil.VerifyData(context, ref NCPublicKey.NullRef, bin32, bin64)
            );

            //No data buffer
            Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
                NCSignatureUtil.VerifyData(context, ref pubKey, [], bin64)
            );

            //No signature
            Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
                NCSignatureUtil.VerifyData(context, ref pubKey, bin32, [])
            );

            //Signature too small
            Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
               NCSignatureUtil.VerifyData(context, ref pubKey, bin32, bin32)
           );

            /*
             *      SIGN DATA
             */

            //Null context
            Assert.ThrowsException<ArgumentNullException>(() =>
                NCSignatureUtil.SignData(null!, ref secKey, bin32, bin32, bin64)
            );

            //Null secret key
            Assert.ThrowsException<ArgumentNullException>(() =>
                NCSignatureUtil.SignData(context, ref NCSecretKey.NullRef, bin32, bin32, bin64)
            );

            //No entropy
            Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
                NCSignatureUtil.SignData(context, ref secKey, [], bin32, bin64)
            );

            //No data
            Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
                NCSignatureUtil.SignData(context, ref secKey, bin32, [], bin64)
            );

            //No signature
            Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
                NCSignatureUtil.SignData(context, ref secKey, bin32, bin32, [])
            );

            //Signature too small
            Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
                NCSignatureUtil.SignData(context, ref secKey, bin32, bin32, bin32)
            );  

            //Entropy too small
            Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
                NCSignatureUtil.SignData(context, ref secKey, bin16, bin32, bin32)
            );

            /*
             * Cipher api
             */

            NoscryptSigner signer = new(context, NCFallbackRandom.Shared);

          
        }

        void IDisposable.Dispose()
        {
            _testLib.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
