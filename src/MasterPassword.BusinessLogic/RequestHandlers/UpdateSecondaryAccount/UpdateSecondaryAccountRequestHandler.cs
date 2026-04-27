using MasterPassword.DataAccess.MongoDbAtlas;
using MasterPassword.DataAccess.MongoDbAtlas.Entities;
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MasterPassword.BusinessLogic.UpdateSecondaryAccount
{
    public interface IUpdateSecondaryAccountRequestHandler
    {
        Task<UpdateSecondaryAccountResponse> HandleAsync(UpdateSecondaryAccountRequest request);
    }

    internal sealed class UpdateSecondaryAccountRequestHandler(IMongoDbRepository Repository, IEncryptor Encryptor) 
        : IUpdateSecondaryAccountRequestHandler
    {
        public async Task<UpdateSecondaryAccountResponse> HandleAsync(UpdateSecondaryAccountRequest request)
        {
            if (request == null)
                return new UpdateSecondaryAccountResponse(false) { ErrorMessage = "No data was recevied in the request" };

            if (string.IsNullOrWhiteSpace(request.PrimaryAccountId))
                return new UpdateSecondaryAccountResponse(false) { ErrorMessage = "Invalid pid" };

            if (string.IsNullOrWhiteSpace(request.SecondaryAccountId))
                return new UpdateSecondaryAccountResponse(false) { ErrorMessage = "Invalid sid" };

            if (string.IsNullOrWhiteSpace(request.UserKey))
                return new UpdateSecondaryAccountResponse(false) { ErrorMessage = "Invalid key" };

            var primaryAccountById = await Repository.LoadPrimaryAccountByIdAsync(request.PrimaryAccountId);
            byte[] encryptionKeyBytes = Encoding.UTF8.GetBytes(request.UserKey);

            //var secondaryAccountIds =
            //    primaryAccountById.SecondaryAccounts.Select(x => x.SecondaryAccountId)
            //                                        .Select(x => Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, x))
            //                                        .ToList();

            //if (!secondaryAccountIds.Contains(request.SecondaryAccountId))
            //    return new UpdateSecondaryAccountResponse(false) { ErrorMessage = "This is not your account. Stop it" };

            SecondaryAccount secondaryAccount = await Repository.LoadSecondaryAccountByIdAsync(request.SecondaryAccountId);
            if(secondaryAccount.PrimaryAccountId != primaryAccountById._id.ToString())
                return new UpdateSecondaryAccountResponse(false) { ErrorMessage = "This is not your account. Stop it" };

            byte[] secondaryAccountId = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, secondaryAccount._id.ToString());

            //int secondaryAccountIndex = primaryAccountById.SecondaryAccounts.FindIndex(x => Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, x.SecondaryAccountId) == secondaryAccount._id.ToString());
            //SecondaryAccountShallow shallow = primaryAccountById.SecondaryAccounts[secondaryAccountIndex];

            string fieldName = request.FieldName.ToLower();

            byte[] value = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, request.Value);

            switch (fieldName)
            {
                case "accountname":
                    secondaryAccount.AccountName = value;
                    break;
                case "username":
                    secondaryAccount.Username = value;
                    break;
                case "password":
                    secondaryAccount.Password = value;
                    break;
                case "url":
                    secondaryAccount.Url = value;
                    await HandleUrlUpdateAsync(secondaryAccount, encryptionKeyBytes, request.Value);
                    break;
                case "category":
                    secondaryAccount.Category = value;
                    break;
                default:
                    return new UpdateSecondaryAccountResponse(true);
            }

            await Repository.UpdateSecondaryAccountAsync(request.SecondaryAccountId, secondaryAccount);
            
            return new UpdateSecondaryAccountResponse(true);
        }

        private async Task HandleUrlUpdateAsync(SecondaryAccount secondaryAccount, byte[] encryptionKeyBytes, string updatedUrl)
        {
            if (string.IsNullOrEmpty(updatedUrl))
            {
                secondaryAccount.FaviconId = null;
                return;
            }

            Uri? uri = null;
            try
            {
                uri = new Uri(updatedUrl);
            }
            catch
            {
                //eat it
                return;
            }

            if (uri is null)
                return;

            string? faviconId = null;
            Favicon? faviconByHost = await Repository.LoadFaviconByHostAsync(uri.Host);
            if(faviconByHost is null)
            {
                string newFaviconId = await Repository.CreateFaviconAsync(uri.Host);
                faviconId = newFaviconId;
            }
            else
            {
                faviconId = faviconByHost._id.ToString();
            }

            secondaryAccount.FaviconId = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, faviconId);

            //Favicon? favicon;
            //if (secondaryAccount.FaviconId is null)
            //{

            //}
            //else
            //{

            //}


            //if(secondaryAccount.FaviconId is not null)
            //{
            //    string faviconId = Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, secondaryAccount.FaviconId);
            //    favicon = await Repository.LoadFaviconByIdAsync(faviconId);

            //    if (favicon is null)
            //        return;

            //    if (favicon.Host == uri.Host)
            //        return;
            //}

            //Favicon? f = await Repository.LoadFaviconByHostAsync(uri.Host);

            //if(f is null)
            //{
            //    var newFaviconId = await Repository.CreateFaviconAsync(uri.Host);
            //    secondaryAccount.FaviconId = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, newFaviconId);
            //    return;
            //}

            //secondaryAccount.FaviconId = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, f._id.ToString());
        }
    }
}
