using MongoDB.Bson.Serialization.Attributes;

namespace MasterPassword.DataAccess.MongoDbAtlas.Entities
{
    [BsonIgnoreExtraElements]
    public class SecondaryAccountShallow
    {
        public byte[] SecondaryAccountId { get; set; }

        public byte[] AccountName { get; set; }

        public byte[] FaviconId { get; set; }
    }
}
