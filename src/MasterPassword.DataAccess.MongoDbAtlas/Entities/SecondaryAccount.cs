using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace MasterPassword.DataAccess.MongoDbAtlas.Entities
{
    [BsonIgnoreExtraElements]
    public class SecondaryAccount
    {
        public ObjectId _id { get; set; }

        public string? PrimaryAccountId { get; set; }

        public byte[] AccountName { get; set; } = null!;

        public byte[]? Url { get; set; }

        public byte[]? Username { get; set; }

        public byte[]? Password { get; set; }

        public byte[]? FaviconId { get; set; }

        public byte[]? Category { get; set; }
    }
}
