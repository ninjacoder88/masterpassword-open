using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;

namespace MasterPassword.DataAccess.MongoDbAtlas.Entities
{
    [BsonIgnoreExtraElements]
    public class PrimaryAccount
    {
        public ObjectId _id { get; set; }

        public string Username { get; set; } = null!;

        public string EmailAddress { get; set; } = null!;

        public string Password { get; set; } = null!;

        public DateTimeOffset LastLoginTime { get; set; }

        public int FailedLoginCount { get; set; }

        public DateTimeOffset CreateTime { get; set; }

        public byte[] Token { get; set; }

        public byte[] TokenExpiration { get; set; }
    }
}
