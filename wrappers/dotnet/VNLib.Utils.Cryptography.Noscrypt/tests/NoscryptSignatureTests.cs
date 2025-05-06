using Microsoft.VisualStudio.TestTools.UnitTesting;

using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

using VNLib.Utils.Cryptography.Noscrypt.Random;
using VNLib.Utils.Cryptography.Noscrypt.Signatures;

namespace VNLib.Utils.Cryptography.Noscrypt.Tests
{
    [TestClass()]
    public class NoscryptSignatureTests : IDisposable
    {

        const string NostrSignatureTestFile = "nostr-signatures.json";

#nullable disable
        private Noscrypt _testLib;
        private JsonDocument _testVectors;
#nullable enable

        [TestInitialize]
        public void Initialize()
        {
            _testLib = Noscrypt.LoadDefaultLibrary();
            _testVectors = JsonDocument.Parse(File.ReadAllText(NostrSignatureTestFile));
        }    

        void IDisposable.Dispose()
        {
            _testLib.Dispose();
            _testVectors.Dispose();
            GC.SuppressFinalize(this);
        }

        private NostrEventTest[] GetExternalNotes()
        {
            return _testVectors.RootElement
             .GetProperty("external_notes")
             .Deserialize<NostrEventTest[]>()!;
        }

        /*
         * Tests publically available notes to verify the signature.
         * These notes are avaiable on most public relays
         */

        [TestMethod]
        public void TestExistingNotes()
        {
            using NCContext ctx = _testLib.AllocContext(NCFallbackRandom.Shared);
            NCSigner signer = new(ctx, NCFallbackRandom.Shared);

            JsonSerializerOptions options = new()
            {
                PropertyNameCaseInsensitive = true,
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };

            foreach (NostrEventTest note in GetExternalNotes())
            {
                object[] evntObjData = [0, note.PublicKey, note.Timestamp, note.Kind, note.Tags, note.Content];
                byte[] eventData = JsonSerializer.SerializeToUtf8Bytes(evntObjData, options);
                byte[] signature = Convert.FromHexString(note.Signature);

                //Verify the signature
                Assert.IsTrue(signer.VerifyData(note.PublicKey, eventData, signature));
            }
        }

        sealed class NostrEventTest
        {
            [JsonPropertyName("id")]
            public required string EventId { get; init; }

            [JsonPropertyName("pubkey")]
            public required string PublicKey { get; init; }

            [JsonPropertyName("created_at")]
            public required long Timestamp { get; init; }

            [JsonPropertyName("kind")]
            public required int Kind { get; init; }

            [JsonPropertyName("sig")]
            public required string Signature { get; init; }

            [JsonPropertyName("tags")]
            public required string[][] Tags { get; init; }

            [JsonPropertyName("content")]
            public required string Content { get; init; }
        }
    }
}
