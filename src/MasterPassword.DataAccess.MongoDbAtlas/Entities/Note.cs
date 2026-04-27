using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace MasterPassword.DataAccess.MongoDbAtlas.Entities
{
    [BsonIgnoreExtraElements]
    public class Note
    {
        public ObjectId _id { get; set; }

        public string SecondaryAccountId { get; set; } = null!;

        public byte[] Title { get; set; }

        public byte[] Description { get; set; }
    }
}
