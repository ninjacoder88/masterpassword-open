using MasterPassword.DataAccess.MongoDbAtlas.Entities;
using Microsoft.Extensions.Configuration;
using MongoDB.Bson;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MasterPassword.DataAccess.MongoDbAtlas
{
    public interface IMongoDbRepository
    {
        //Task AddPrimaryAccountShallowReferencesAsync(string id, SecondaryAccountShallow secondaryAccountShallow);

        Task<string> CreateFaviconAsync(string host);

        Task<string> CreateNoteAsync(Note note);

        Task<string> CreatePrimaryAccountAsync(PrimaryAccount primaryAccount);

        Task<string> CreateSecondaryAccountAsync(SecondaryAccount secondaryAccount);

        Task DeleteNoteAsync(string id);

        Task DeleteSecondaryAccountAsync(string id);

        Task<List<Favicon>> LoadFaviconsAsync();

        Task<Favicon?> LoadFaviconByIdAsync(string faviconId);

        Task<Favicon?> LoadFaviconByHostAsync(string host);

        Task<List<Note>> LoadNotesAsync(List<string> ids);

        Task<PrimaryAccount> LoadPrimaryAccountByEmailAddressAsync(string emailAddress);

        Task<PrimaryAccount> LoadPrimaryAccountByIdAsync(string id);

        Task<PrimaryAccount> LoadPrimaryAccountByUsernameAsync(string username);

        Task<SecondaryAccount> LoadSecondaryAccountByIdAsync(string id);

        Task<List<SecondaryAccount>> LoadSecondaryAccountsForPrimaryAccountAsync(string id);

        Task<List<Note>> LoadNotesForSecondaryAccountAsync(string id);

        Task<Note> LoadNoteAsync(string id);

        Task LoginAsync(ObjectId objectId, byte[] token, byte[] tokenExpiration);

        Task LogoutAsync(string id);

        Task RefreshTokenAsync(string id, byte[] token, byte[] tokenExpiration);

        //Task RemovePrimaryAccountShallowReferencesAsync(string id, SecondaryAccountShallow secondaryAccountShallow);

        Task UpdateFailedLoginCountAsync(ObjectId objectId, int updatedCount);

        Task UpdateFaviconAsync(ObjectId id, Favicon favicon);

        Task UpdateNoteAsync(string id, Note note);

        Task UpdateSecondaryAccountAsync(string id, SecondaryAccount secondaryAccount);

        //Task UpdateSecondaryAccountNoteIdsAsync(string id, byte[] noteId);

        //Task UpdateSecondaryAccountShallowAsync(string primaryAccountId, int index, SecondaryAccountShallow secondaryAccount); 
    }

    internal class MongoDbRepository : IMongoDbRepository
    {
        public MongoDbRepository(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("MongoDbAtlas");
        }

        public MongoDbRepository(string connectionString)
        {
            _connectionString = connectionString;
        }

        //public async Task AddPrimaryAccountShallowReferencesAsync(string id, SecondaryAccountShallow secondaryAccountShallow)
        //{
        //    ObjectId objectId = ObjectId.Parse(id);//TODO: tryparse

        //    UpdateDefinitionBuilder<PrimaryAccount> updateDefinitionBuilder = new UpdateDefinitionBuilder<PrimaryAccount>();
        //    UpdateDefinition<PrimaryAccount> updateDefinition = updateDefinitionBuilder.AddToSet(x => x.SecondaryAccounts, secondaryAccountShallow);

        //    var primaryAccountCollection = GetPrimaryAccountCollection();
        //    await primaryAccountCollection.FindOneAndUpdateAsync(x => x._id == objectId, updateDefinition);
        //}

        public async Task<string> CreateFaviconAsync(string host)
        {
            var faviconCollection = GetFaviconCollection();
            var favicon = new Favicon() { Host = host, Url = null, UpdateTime = DateTimeOffset.Now };
            await faviconCollection.InsertOneAsync(favicon);
            return favicon._id.ToString();
        }

        public async Task<string> CreateNoteAsync(Note note)
        {
            var notesCollection = GetNotesCollection();
            await notesCollection.InsertOneAsync(note);
            return note._id.ToString();
        }

        public async Task<string> CreatePrimaryAccountAsync(PrimaryAccount primaryAccount)
        {
            var primaryAccountsCollection = GetPrimaryAccountCollection();
            await primaryAccountsCollection.InsertOneAsync(primaryAccount);
            return primaryAccount._id.ToString();
        }

        public async Task<string> CreateSecondaryAccountAsync(SecondaryAccount secondaryAccount)
        {
            var secondaryAccountsCollection = GetSecondaryAccountCollection();
            await secondaryAccountsCollection.InsertOneAsync(secondaryAccount);
            return secondaryAccount._id.ToString();
        }

        public async Task DeleteNoteAsync(string id)
        {
            //TODO: determine if an entirely new record is created
            ObjectId objectId = ObjectId.Parse(id);//TODO: tryparse

            var notesCollection = GetNotesCollection();
            await notesCollection.FindOneAndDeleteAsync(x => x._id == objectId);
        }

        public async Task DeleteSecondaryAccountAsync(string id)
        {
            //TODO: determine if an entirely new record is created
            ObjectId objectId = ObjectId.Parse(id);//TODO: tryparse

            var secondaryAccountsCollection = GetSecondaryAccountCollection();
            await secondaryAccountsCollection.FindOneAndDeleteAsync(x => x._id == objectId);
        }

        public async Task<List<Favicon>> LoadFaviconsAsync()
        {
            var faviconCollection = GetFaviconCollection();
            var cursor = await faviconCollection.FindAsync(x => true);
            return await cursor.ToListAsync();
        }

        public async Task<Favicon?> LoadFaviconByIdAsync(string faviconId)
        {
            ObjectId objectId = ObjectId.Parse(faviconId);
            var faviconCollection = GetFaviconCollection();
            var list = await faviconCollection.FilterAsync(x => x._id == objectId);
            return list.SingleOrDefault();
        }

        public async Task<Favicon?> LoadFaviconByHostAsync(string host)
        {
            var faviconCollection = GetFaviconCollection();
            var list = await faviconCollection.FilterAsync(x => x.Host == host);
            return list.SingleOrDefault();
        }

        public async Task<List<Note>> LoadNotesAsync(List<string> ids)
        {
            if (ids == null)
                return new List<Note>();

            if (!ids.Any())
                return new List<Note>();

            List<ObjectId> objectIds = new List<ObjectId>();
            foreach (var id in ids)
            {
                if (!ObjectId.TryParse(id, out ObjectId objectId))
                    continue;
                objectIds.Add(objectId);
            }

            var notesCollection = GetNotesCollection();
            return await notesCollection.FilterAsync(x => objectIds.Contains(x._id));
        }

        public async Task<PrimaryAccount> LoadPrimaryAccountByEmailAddressAsync(string emailAddress)
        {
            if (string.IsNullOrEmpty(emailAddress))
                return null;

            var primaryAccountCollection = GetPrimaryAccountCollection();
            var primaryAccountsWithEmail = await primaryAccountCollection.FilterAsync(x => x.EmailAddress == emailAddress);

            if (primaryAccountsWithEmail.Count == 0)
                return null;

            if (primaryAccountsWithEmail.Count == 1)
                return primaryAccountsWithEmail.Single();

            return null;
        }

        public async Task<PrimaryAccount> LoadPrimaryAccountByIdAsync(string id)
        {
            if (string.IsNullOrEmpty(id))
                return null;

            if (!ObjectId.TryParse(id, out ObjectId objectId))
                return null;

            var primaryAccountCollection = GetPrimaryAccountCollection();
            var primaryAccountsWithId = await primaryAccountCollection.FilterAsync(x => x._id == objectId);

            if (primaryAccountsWithId.Count == 0)
                return null;

            if (primaryAccountsWithId.Count == 1)
                return primaryAccountsWithId.Single();

            return null;
        }

        public async Task<PrimaryAccount> LoadPrimaryAccountByUsernameAsync(string username)
        {
            if (string.IsNullOrEmpty(username))
                return null;

            var primaryAccountCollection = GetPrimaryAccountCollection();
            var primaryAccountsWithUsername = await primaryAccountCollection.FilterAsync(x => x.Username == username);

            if (primaryAccountsWithUsername.Count == 0)
                return null;

            if (primaryAccountsWithUsername.Count == 1)
                return primaryAccountsWithUsername.Single();

            return null;
        }

        public async Task<SecondaryAccount> LoadSecondaryAccountByIdAsync(string id)
        {
            if (string.IsNullOrEmpty(id))
                return null;

            if (!ObjectId.TryParse(id, out ObjectId objectId))
                return null;

            var secondaryAccountCollection = GetSecondaryAccountCollection();
            var secondaryAccountsWithId = await secondaryAccountCollection.FilterAsync(x => x._id == objectId);

            if (secondaryAccountsWithId.Count == 0)
                return null;

            if (secondaryAccountsWithId.Count == 1)
                return secondaryAccountsWithId.Single();

            return null;
        }

        public async Task<List<SecondaryAccount>> LoadSecondaryAccountsForPrimaryAccountAsync(string id)
        {
            if (string.IsNullOrEmpty(id))
                return new List<SecondaryAccount>();

            if (!ObjectId.TryParse(id, out ObjectId objectId))
                return new List<SecondaryAccount>();

            var secondaryAccountCollection = GetSecondaryAccountCollection();
            return await secondaryAccountCollection.FilterAsync(x => x.PrimaryAccountId == id);
        }

        public async Task<List<Note>> LoadNotesForSecondaryAccountAsync(string id)
        {
            if (string.IsNullOrEmpty(id))
                return new List<Note>();

            if (!ObjectId.TryParse(id, out ObjectId objectId))
                return new List<Note>();

            var notesCollection = GetNotesCollection();
            return await notesCollection.FilterAsync(x => x.SecondaryAccountId == id);
        }

        public async Task<Note> LoadNoteAsync(string id)
        {
            if (string.IsNullOrEmpty(id))
                return null;

            if (!ObjectId.TryParse(id, out ObjectId objectId))
                return null;

            var notes = await GetNotesCollection().FilterAsync(x => x._id == objectId);
            return notes.SingleOrDefault();
        }

        public async Task LoginAsync(ObjectId objectId, byte[] token, byte[] tokenExpiration)
        {
            UpdateDefinitionBuilder<PrimaryAccount> updateDefinitionBuilder = new UpdateDefinitionBuilder<PrimaryAccount>();
            UpdateDefinition<PrimaryAccount> updateDefinition = updateDefinitionBuilder.Set(x => x.LastLoginTime, DateTimeOffset.UtcNow)
                .Set(x => x.FailedLoginCount, 0)
                .Set(x => x.Token, token)
                .Set(x => x.TokenExpiration, tokenExpiration);

            var primaryAccountsCollection = GetPrimaryAccountCollection();
            await primaryAccountsCollection.FindOneAndUpdateAsync(x => x._id == objectId, updateDefinition);
        }

        public async Task LogoutAsync(string id)
        {
            ObjectId objectId = ObjectId.Parse(id);//TODO: tryparse

            UpdateDefinitionBuilder<PrimaryAccount> updateDefinitionBuilder = new UpdateDefinitionBuilder<PrimaryAccount>();
            UpdateDefinition<PrimaryAccount> updateDefinition = updateDefinitionBuilder.Set(x => x.Token, null)
                .Set(x => x.TokenExpiration, null);

            var primaryAccountsCollection = GetPrimaryAccountCollection();
            await primaryAccountsCollection.FindOneAndUpdateAsync(x => x._id == objectId, updateDefinition);
        }

        public async Task RefreshTokenAsync(string id, byte[] token, byte[] tokenExpiration)
        {
            ObjectId objectId = ObjectId.Parse(id);

            UpdateDefinitionBuilder<PrimaryAccount> updateDefinitionBuilder = new UpdateDefinitionBuilder<PrimaryAccount>();
            UpdateDefinition<PrimaryAccount> updateDefinition = updateDefinitionBuilder.Set(x => x.LastLoginTime, DateTimeOffset.UtcNow)
                .Set(x => x.Token, token)
                .Set(x => x.TokenExpiration, tokenExpiration);

            var primaryAccountsCollection = GetPrimaryAccountCollection();
            await primaryAccountsCollection.FindOneAndUpdateAsync(x => x._id == objectId, updateDefinition);
        }

        //public async Task RemovePrimaryAccountShallowReferencesAsync(string id, SecondaryAccountShallow secondaryAccountShallow)
        //{
        //    //TODO: determine if an entirely new record is created
        //    ObjectId objectId = ObjectId.Parse(id);//TODO: tryparse

        //    var primaryAccountCollection = GetPrimaryAccountCollection();
        //    var primaryAccounts = await primaryAccountCollection.FilterAsync(x => x._id == objectId);

        //    var primaryAccount = primaryAccounts.Single();

        //    var secondaryAccount = primaryAccount.SecondaryAccounts.Where(x => x.SecondaryAccountId.SequenceEqual(secondaryAccountShallow.SecondaryAccountId)).Single();
        //    primaryAccount.SecondaryAccounts.Remove(secondaryAccount);

        //    UpdateDefinitionBuilder<PrimaryAccount> updateDefinitionBuilder = new UpdateDefinitionBuilder<PrimaryAccount>();
        //    UpdateDefinition<PrimaryAccount> updateDefinition = updateDefinitionBuilder.Set(x => x.SecondaryAccounts, primaryAccount.SecondaryAccounts);

        //    await primaryAccountCollection.FindOneAndUpdateAsync(x => x._id == objectId, updateDefinition);
        //}

        public async Task UpdateFailedLoginCountAsync(ObjectId objectId, int updatedCount)
        {
            UpdateDefinitionBuilder<PrimaryAccount> updateDefinitionBuilder = new UpdateDefinitionBuilder<PrimaryAccount>();
            UpdateDefinition<PrimaryAccount> updateDefinition = updateDefinitionBuilder.Set(x => x.FailedLoginCount, updatedCount);

            var primaryAccountsCollection = GetPrimaryAccountCollection();
            await primaryAccountsCollection.FindOneAndUpdateAsync(x => x._id == objectId, updateDefinition);
        }

        public async Task UpdateFaviconAsync(ObjectId id, Favicon favicon)
        {
            UpdateDefinition<Favicon> updateDefinition = 
                new UpdateDefinitionBuilder<Favicon>()
                //.Set(x => x.Path, favicon.Path)
                .Set(x => x.Host, favicon.Host)
                .Set(x => x.Url, favicon.Url)
                .Set(x => x.Data, favicon.Data)
                .Set(x => x.UpdateTime, favicon.UpdateTime);

            var faviconCollection = GetFaviconCollection();
            await faviconCollection.FindOneAndUpdateAsync(x => x._id == id, updateDefinition);
        }

        public async Task UpdateNoteAsync(string id, Note note)
        {
            //TODO: determine if an entirely new record is created
            ObjectId objectId = ObjectId.Parse(id);//TODO: tryparse

            var notesCollection = GetNotesCollection();
            await notesCollection.FindOneAndReplaceAsync(x => x._id == objectId, note);
        }

        public async Task UpdateSecondaryAccountAsync(string id, SecondaryAccount secondaryAccount)
        {
            ObjectId objectId = ObjectId.Parse(id);//TODO: tryparse

            UpdateDefinitionBuilder<SecondaryAccount> updateDefinitionBuilder = new UpdateDefinitionBuilder<SecondaryAccount>();
            UpdateDefinition<SecondaryAccount> updateDefinition =
                updateDefinitionBuilder.Set(x => x.AccountName, secondaryAccount.AccountName)
                                        .Set(x => x.Password, secondaryAccount.Password)
                                        .Set(x => x.Url, secondaryAccount.Url)
                                        .Set(x => x.Username, secondaryAccount.Username)
                                        .Set(x => x.PrimaryAccountId, secondaryAccount.PrimaryAccountId)
                                        .Set(x => x.FaviconId, secondaryAccount.FaviconId)
                                        .Set(x => x.Category, secondaryAccount.Category);

            var secondaryAccountsCollection = GetSecondaryAccountCollection();
            await secondaryAccountsCollection.FindOneAndUpdateAsync(x => x._id == objectId, updateDefinition);
        }

        //public async Task UpdateSecondaryAccountNoteIdsAsync(string id, byte[] noteId)
        //{
        //    //TODO: determine if an entirely new record is created
        //    ObjectId objectId = ObjectId.Parse(id);//TODO: tryparse

        //    UpdateDefinitionBuilder<SecondaryAccount> updateDefinitionBuilder = new UpdateDefinitionBuilder<SecondaryAccount>();
        //    UpdateDefinition<SecondaryAccount> updateDefinition = updateDefinitionBuilder.AddToSet(x => x.NoteIds, noteId);

        //    var secondaryAccountsCollection = GetSecondaryAccountCollection();
        //    await secondaryAccountsCollection.FindOneAndUpdateAsync(x => x._id == objectId, updateDefinition);
        //}

        //public async Task UpdateSecondaryAccountShallowAsync(string primaryAccountId, int index, SecondaryAccountShallow secondaryAccount)
        //{
        //    ObjectId objectId = ObjectId.Parse(primaryAccountId);
        //    var primaryAccountCollection = GetPrimaryAccountCollection();
        //    var list = await primaryAccountCollection.FilterAsync(x => x._id == objectId);
        //    var primaryAccount = list.Single();

        //    UpdateDefinition<PrimaryAccount> updateDefinition =
        //        new UpdateDefinitionBuilder<PrimaryAccount>()
        //        .Set(x => x.SecondaryAccounts[index].FaviconId, secondaryAccount.FaviconId)
        //        .Set(x => x.SecondaryAccounts[index].AccountName, secondaryAccount.AccountName);

        //    await primaryAccountCollection.FindOneAndUpdateAsync(x => x._id == objectId, updateDefinition);
        //}

        private IMongoCollection<T> GetCollection<T>(string collectionName)
        {
            var client = new MongoClient(_connectionString);
            var database = client.GetDatabase("MasterPassword");
            return database.GetCollection<T>(collectionName);
        }

        private IMongoCollection<Favicon> GetFaviconCollection()
        {
            return GetCollection<Favicon>("Favicons");
        }

        private IMongoCollection<Note> GetNotesCollection()
        {
            return GetCollection<Note>("Notes");
        }

        private IMongoCollection<PrimaryAccount> GetPrimaryAccountCollection()
        {
            return GetCollection<PrimaryAccount>("PrimaryAccounts");
        }

        private IMongoCollection<SecondaryAccount> GetSecondaryAccountCollection()
        {
            return GetCollection<SecondaryAccount>("SecondaryAccounts");
        }

        private readonly string _connectionString;
    }
}
