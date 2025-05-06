using Microsoft.VisualStudio.TestTools.UnitTesting;

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using VNLib.Utils.Cryptography.Noscrypt.Random;

namespace VNLib.Utils.Cryptography.Noscrypt.Tests
{
    [TestClass()]
    public class NCKeyUtilTests
    {
        [TestMethod()]
        public void AsSecretKeyTest()
        {
            //Empty span should raise exception
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => NCKeyUtil.AsSecretKey(default));

            Span<byte> dummySecKey = stackalloc byte[NCSecretKey.Size];

            NCFallbackRandom.Shared.GetRandomBytes(dummySecKey);

            {
                ref NCSecretKey key = ref NCKeyUtil.AsSecretKey(dummySecKey);

                ref readonly byte b1 = ref Unsafe.As<NCSecretKey, byte>(ref key);
                ref readonly byte b2 = ref MemoryMarshal.GetReference(dummySecKey);

                //Check that the memory address of the secret key is the same as the span
                Assert.IsTrue(Unsafe.AreSame(in b1, in b2));

                //Dereference and compare
                Assert.IsTrue(b1 == b2);
            }

            {
                ref readonly NCSecretKey key = ref NCKeyUtil.AsSecretKey((ReadOnlySpan<byte>)dummySecKey);

                ref readonly byte b1 = ref Unsafe.As<NCSecretKey, byte>(ref Unsafe.AsRef(in key));
                ref readonly byte b2 = ref MemoryMarshal.GetReference(dummySecKey);

                //Check that the memory address of the secret key is the same as the span
                Assert.IsTrue(Unsafe.AreSame(in b1, in b2));

                //Dereference and compare
                Assert.IsTrue(b1 == b2);
            }
        }

        [TestMethod()]
        public void AsPublicKeyTest()
        {
            //Empty span should raise exception
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => NCKeyUtil.AsPublicKey(default));

            Span<byte> dummyPubKey = stackalloc byte[NCPublicKey.Size];

            NCFallbackRandom.Shared.GetRandomBytes(dummyPubKey);

            {
                ref NCPublicKey key = ref NCKeyUtil.AsPublicKey(dummyPubKey);

                ref readonly byte b1 = ref Unsafe.As<NCPublicKey, byte>(ref key);
                ref readonly byte b2 = ref MemoryMarshal.GetReference(dummyPubKey);

                //Check that the memory address of the secret key is the same as the span
                Assert.IsTrue(Unsafe.AreSame(in b1, in b2));

                //Dereference and compare
                Assert.IsTrue(b1 == b2);
            }

            {
                ref readonly NCPublicKey key = ref NCKeyUtil.AsPublicKey((ReadOnlySpan<byte>)dummyPubKey);

                ref readonly byte b1 = ref Unsafe.As<NCPublicKey, byte>(ref Unsafe.AsRef(in key));
                ref readonly byte b2 = ref MemoryMarshal.GetReference(dummyPubKey);

                //Check that the memory address of the secret key is the same as the span
                Assert.IsTrue(Unsafe.AreSame(in b1, in b2));

                //Dereference and compare
                Assert.IsTrue(b1 == b2);
            }
        }

        [TestMethod()]
        public void AsSpanTest()
        {
            //Null keys should return empty span
            Assert.IsTrue(NCKeyUtil.AsSpan(ref Unsafe.AsRef(in NCSecretKey.NullRef)).IsEmpty);
            Assert.IsTrue(NCKeyUtil.AsSpan(ref Unsafe.AsRef(in NCPublicKey.NullRef)).IsEmpty);

            Span<byte> dummySecKey = stackalloc byte[NCSecretKey.Size];
            Span<byte> dummyPubKey = stackalloc byte[NCPublicKey.Size];

            NCFallbackRandom.Shared.GetRandomBytes(dummySecKey);
            NCFallbackRandom.Shared.GetRandomBytes(dummyPubKey);

            //Test mutable spans
            {
                ref NCSecretKey secKey = ref NCKeyUtil.AsSecretKey(dummySecKey);
                ref NCPublicKey pubKey = ref NCKeyUtil.AsPublicKey(dummyPubKey);

                Span<byte> secSpan = NCKeyUtil.AsSpan(ref secKey);
                Span<byte> pubSpan = NCKeyUtil.AsSpan(ref pubKey);

                Assert.IsTrue(secSpan.SequenceEqual(dummySecKey));
                Assert.IsTrue(pubSpan.SequenceEqual(dummyPubKey));
            }

            //Test readonly spans
            {
                ref readonly NCSecretKey secKey = ref NCKeyUtil.AsSecretKey((ReadOnlySpan<byte>)dummySecKey);
                ref readonly NCPublicKey pubKey = ref NCKeyUtil.AsPublicKey((ReadOnlySpan<byte>)dummyPubKey);

                ReadOnlySpan<byte> secSpan = NCKeyUtil.AsReadonlySpan(in secKey);
                ReadOnlySpan<byte> pubSpan = NCKeyUtil.AsReadonlySpan(in pubKey);

                Assert.IsTrue(secSpan.SequenceEqual(dummySecKey));
                Assert.IsTrue(pubSpan.SequenceEqual(dummyPubKey));
            }
        }
    }


}