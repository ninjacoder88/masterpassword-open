using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;

namespace MasterPassword.DataAccess.MongoDbAtlas.Entities
{
    [BsonIgnoreExtraElements]
    public class Favicon
    {
        public ObjectId _id { get; set; }

        public string Host { get; set; } = string.Empty;

        //public string Path { get; set; }

        public DateTimeOffset UpdateTime { get; set; } = DateTimeOffset.MinValue;


        public string? Url { get; set; }

        public byte[]? Data { get; set; }
    }
}
