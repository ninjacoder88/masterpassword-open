using MasterPassword.DataAccess.MongoDbAtlas;
using MasterPassword.DataAccess.MongoDbAtlas.Entities;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MasterPassword.BusinessLogic.LoadSecondaryAccount
{
    public interface ILoadSecondaryAccountRequestHandler
    {
        Task<LoadSecondaryAccountResponse> HandleAsync(LoadSecondaryAccountRequest request);
    }

    internal sealed class LoadSecondaryAccountRequestHandler(IMongoDbRepository Repository, IEncryptor Encryptor) : ILoadSecondaryAccountRequestHandler
    {
        public async Task<LoadSecondaryAccountResponse> HandleAsync(LoadSecondaryAccountRequest request)
        {
            if (request == null)
                return new LoadSecondaryAccountResponse(false) { ErrorMessage = "No data was recevied in the request" };

            if (string.IsNullOrEmpty(request.Id))
                return new LoadSecondaryAccountResponse(false) { ErrorMessage = "Invalid sid" };

            if (string.IsNullOrEmpty(request.PrimaryAccountId))
                return new LoadSecondaryAccountResponse(false) { ErrorMessage = "Invalid pid" };

            var primaryAccountById = await Repository.LoadPrimaryAccountByIdAsync(request.PrimaryAccountId);
            byte[] encryptionKeyBytes = Encoding.UTF8.GetBytes(request.UserKey);

            //var secondaryAccountIds = 
            //    primaryAccountById.SecondaryAccounts.Select(x => x.SecondaryAccountId)
            //                                        .Select(x => Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, x))
            //                                        .ToList();

            //if (!secondaryAccountIds.Contains(request.Id))
            //    return new LoadSecondaryAccountResponse(false) { ErrorMessage = "This is not your account. Stop it" };

            SecondaryAccount secondaryAccount = await Repository.LoadSecondaryAccountByIdAsync(request.Id);
            if(secondaryAccount.PrimaryAccountId != primaryAccountById._id.ToString())
                return new LoadSecondaryAccountResponse(false) { ErrorMessage = "This is not your account. Stop it" };

            string accountName =Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, secondaryAccount.AccountName);
            string username = Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, secondaryAccount.Username);
            string password = Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, secondaryAccount.Password);
            string url = Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, secondaryAccount.Url);

            return new LoadSecondaryAccountResponse(true) { AccountName = accountName, Username = username, Password = password, Url = url};
        }
    }
}
