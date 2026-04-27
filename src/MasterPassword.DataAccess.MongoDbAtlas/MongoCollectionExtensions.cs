using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Threading.Tasks;

namespace MasterPassword.DataAccess.MongoDbAtlas
{
    internal static class MongoCollectionExtensions
    {
        public static async Task<List<T>> FilterAsync<T>(this IMongoCollection<T> source, Expression<Func<T, bool>> expression)
        {
            var cursor = await source.FindAsync(expression);
            return await cursor.ToListAsync();
        }
    }
}
