using MasterPassword.BusinessLogic.DeleteSecondaryAccount;
using MasterPassword.DataAccess.MongoDbAtlas;
using MasterPassword.DataAccess.MongoDbAtlas.Entities;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace MasterPassword.BusinessLogic.CreateSecondaryAccount
{
    public interface ICreateSecondaryAccountRequestHandler
    {
        Task<CreateSecondaryAccountResponse> HandleAsync(CreateSecondaryAccountRequest request);
    }

    internal sealed class CreateSecondaryAccountRequestHandler(IMongoDbRepository Repository, IEncryptor Encryptor) : ICreateSecondaryAccountRequestHandler
    {
        public async Task<CreateSecondaryAccountResponse> HandleAsync(CreateSecondaryAccountRequest request)
        {
            if (request is null)
                return new CreateSecondaryAccountResponse(false) { ErrorMessage = "No data was received in the request" };

            if(string.IsNullOrEmpty(request.PrimaryAccountId))
                return new CreateSecondaryAccountResponse(false) { ErrorMessage = "Invalid pid" };

            if (string.IsNullOrWhiteSpace(request.UserKey))
                return new CreateSecondaryAccountResponse(false) { ErrorMessage = "Invalid key" };

            var primaryAccount = await Repository.LoadPrimaryAccountByIdAsync(request.PrimaryAccountId);

            if (primaryAccount is null)
                return new CreateSecondaryAccountResponse(false) { ErrorMessage = "Could not find primary account" };

            byte[] encryptionKeyBytes = Encoding.UTF8.GetBytes(request.UserKey);

            byte[] encryptedAccountName = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, request.AccountName);
            byte[] encryptedUsername = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, request.Username);
            byte[] encryptedPassword = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, request.Password);
            byte[] encryptedUrl = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, request.Url);

            var secondaryAccount = new SecondaryAccount { 
                AccountName = encryptedAccountName, 
                Password = encryptedPassword, 
                Url = encryptedUrl, 
                Username = encryptedUsername, 
                //NoteIds = new List<byte[]>(),
                PrimaryAccountId = primaryAccount._id.ToString()
            };

            var secondaryAccountId = await Repository.CreateSecondaryAccountAsync(secondaryAccount);

            byte[] encryptedSecondaryAccountId = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, secondaryAccountId);

            byte[]? encryptedFaviconId = null;
            if (!string.IsNullOrWhiteSpace(request.Url))
            {
                string faviconId;
                var uri = new Uri(request.Url);
                var favicon = await Repository.LoadFaviconByHostAsync(uri.Host);
                if (favicon == null)
                    faviconId = await Repository.CreateFaviconAsync(uri.Host);
                else
                    faviconId = favicon._id.ToString();

                encryptedFaviconId = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, faviconId);
            }

            //var secondaryAccountShallow = new SecondaryAccountShallow { 
            //    SecondaryAccountId = encryptedSecondaryAccountId, 
            //    AccountName = encryptedAccountName,
            //    FaviconId = encryptedFaviconId
            //};

            //await Repository.AddPrimaryAccountShallowReferencesAsync(request.PrimaryAccountId, secondaryAccountShallow);

            return new CreateSecondaryAccountResponse(true) { Id = secondaryAccountId };
        }
    }
}
