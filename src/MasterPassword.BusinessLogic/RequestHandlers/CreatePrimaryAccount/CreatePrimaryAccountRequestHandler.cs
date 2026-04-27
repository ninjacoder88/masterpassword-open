using MasterPassword.DataAccess.MongoDbAtlas;
using MasterPassword.DataAccess.MongoDbAtlas.Entities;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace MasterPassword.BusinessLogic.CreatePrimaryAccount
{
    public interface ICreatePrimaryAccountRequestHandler
    {
        Task<CreatePrimaryAccountResponse> HandleAsync(CreatePrimaryAccountRequest request);
    }

    internal sealed class CreatePrimaryAccountRequestHandler(IMongoDbRepository Repository, IEncryptor Encryptor)
        : ICreatePrimaryAccountRequestHandler
    {
        public async Task<CreatePrimaryAccountResponse> HandleAsync(CreatePrimaryAccountRequest request)
        {
            if (request == null)
                return new CreatePrimaryAccountResponse(false) { ErrorMessage = "No data was received in the request" };

            if (string.IsNullOrEmpty(request.Username))
                return new CreatePrimaryAccountResponse(false) { ErrorMessage = "Username must have a value" };

            if (request.Username.Length < AppConfiguration.UsernameMinimumLength)
                return new CreatePrimaryAccountResponse(false) { ErrorMessage = $"Username must be at least {AppConfiguration.UsernameMinimumLength} characters" };

            string lowercaseUsername = request.Username.ToLower();

            var primaryAccountByUsername = await Repository.LoadPrimaryAccountByUsernameAsync(lowercaseUsername);

            if (primaryAccountByUsername != null)
                return new CreatePrimaryAccountResponse(false) { ErrorMessage = "Unable to create account. Either the username has already been registered or the account is configured incorrectly" };

            //if(primaryAccountsWithUsername.Count > 0)
            //    return new CreatePrimaryAccountResponse(false) { ErrorMessage = "Unable to create account. Username has already been registered" };

            if (string.IsNullOrEmpty(request.Password))
                return new CreatePrimaryAccountResponse(false) { ErrorMessage = "Password must have a value" };

            if (request.Password.Length < AppConfiguration.PasswordMinimumLength)
                return new CreatePrimaryAccountResponse(false) { ErrorMessage = $"Password must be at least {AppConfiguration.PasswordMinimumLength} characters" };

            string lowercaseEmail = request.EmailAddress.ToLower().Trim();

            var primaryAccountByEmail = await Repository.LoadPrimaryAccountByEmailAddressAsync(lowercaseEmail);

            if (primaryAccountByEmail != null)
                return new CreatePrimaryAccountResponse(false) { ErrorMessage = "Unable to create account. Either the email address has already been registered or the account is configured incorrectly" };

            if (string.IsNullOrEmpty(lowercaseEmail))
                return new CreatePrimaryAccountResponse(false) { ErrorMessage = "Email address must have a value" };

            if (!lowercaseEmail.Contains("@"))
                return new CreatePrimaryAccountResponse(false) { ErrorMessage = "Invalid email address" };

            var hashedPassword = Encryptor.HashEncrypt(request.Password);

            var id = await Repository.CreatePrimaryAccountAsync(new PrimaryAccount() { 
                Username = lowercaseUsername, 
                EmailAddress = lowercaseEmail, 
                Password = hashedPassword, 
                //SecondaryAccounts = new List<SecondaryAccountShallow>(),
                CreateTime = DateTimeOffset.UtcNow
            });

            return new CreatePrimaryAccountResponse(true) { Id = id};
        }
    }
}
