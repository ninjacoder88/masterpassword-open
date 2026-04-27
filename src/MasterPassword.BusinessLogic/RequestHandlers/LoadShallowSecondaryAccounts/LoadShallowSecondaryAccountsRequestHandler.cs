using MasterPassword.DataAccess.MongoDbAtlas;
using MasterPassword.DataAccess.MongoDbAtlas.Entities;
using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MasterPassword.BusinessLogic.LoadSecondaryAccounts
{
    public interface ILoadShallowSecondaryAccountsRequestHandler
    {
        Task<LoadShallowSecondaryAccountsResponse> HandleAsync(LoadShallowSecondaryAccountsRequest request);
    }

    internal sealed class LoadShallowSecondaryAccountsRequestHandler(IMongoDbRepository Repository, IEncryptor Encryptor, IMemoryCache MemoryCache) 
        : ILoadShallowSecondaryAccountsRequestHandler
    {
        public async Task<LoadShallowSecondaryAccountsResponse> HandleAsync(LoadShallowSecondaryAccountsRequest request)
        {
            if (request == null)
                return new LoadShallowSecondaryAccountsResponse(false) { ErrorMessage = "No data was recevied in the request" };

            if (string.IsNullOrEmpty(request.PrimaryAccountId))
                return new LoadShallowSecondaryAccountsResponse(false) { ErrorMessage = "Invalid pid" };

            var primaryAccountById = await Repository.LoadPrimaryAccountByIdAsync(request.PrimaryAccountId);

            if (primaryAccountById == null)
                return new LoadShallowSecondaryAccountsResponse(false) { ErrorMessage = "Unable to locate primary account" };

            byte[] encryptionKeyBytes = Encoding.UTF8.GetBytes(request.UserKey);

            List<SecondaryAccount> secondaryAccounts = await Repository.LoadSecondaryAccountsForPrimaryAccountAsync(primaryAccountById._id.ToString());

            List<ShallowSecondaryAccount> list = new List<ShallowSecondaryAccount>();
            foreach(SecondaryAccount secondaryAccount in secondaryAccounts)
            {
                try
                {
                    string faviconPath = "/tempicon.png";
                    if(secondaryAccount.FaviconId is not null)
                    {
                        string faviconId = Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, secondaryAccount.FaviconId);
                        if(MemoryCache.TryGetValue($"favicon-{faviconId}", out string? cachePath))
                        {
                            if(!string.IsNullOrEmpty(cachePath))
                                faviconPath = cachePath;
                        }
                        else
                        {
                            Favicon? favicon = await Repository.LoadFaviconByIdAsync(faviconId);
                            if (favicon is not null)
                            {
                                faviconPath = favicon.Url;
                                MemoryCache.Set($"favicon-{faviconId}", favicon.Url);
                            }      
                        }  
                    }
                    //else
                    //{
                    //    if(secondaryAccount.Url is not null)
                    //    { 
                    //        if(secondaryAccount.Url.Length > 0)
                    //        {
                    //            string url = Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, secondaryAccount.Url);
                    //            if (!string.IsNullOrEmpty(url))
                    //            {
                    //                Uri uri = new Uri(url);
                    //                Favicon? favicon = await Repository.LoadFaviconByHostAsync(uri.Host);
                    //                if(favicon is not null)
                    //                {

                    //                }
                    //            }
                    //        }
                    //    }
                        
                    //}

                    list.Add(new ShallowSecondaryAccount
                    {
                        Id = secondaryAccount._id.ToString(),// Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, secondaryAccount.SecondaryAccountId),
                        AccountName = Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, secondaryAccount.AccountName),
                        Category = secondaryAccount.Category == null ? "" : Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, secondaryAccount.Category),
                        Favicon = faviconPath
                    });
                }
                catch(Exception ex)
                {
                    //eat it for now
                }
            }

            var decryptedAccounts =
                list
                .OrderBy(x => x.AccountName)
                .ToList();

            return new LoadShallowSecondaryAccountsResponse(true) { Accounts = decryptedAccounts };
        }
    }
}
