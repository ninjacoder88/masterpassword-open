using MasterPassword.BusinessLogic.RequestHandlers;
using MasterPassword.DataAccess.MongoDbAtlas;
using System;
using System.Text;
using System.Threading.Tasks;

namespace MasterPassword.BusinessLogic.Login
{
    public interface ILoginRequestHandler
    {
        Task<LoginResponse> HandleAsync(LoginRequest model);
    }

    internal sealed class LoginRequestHandler(IMongoDbRepository Repository, IEncryptor Encryptor, 
        IKeyDeriver KeyDeriver, ITokenGenerator TokenGenerator) : ILoginRequestHandler
    {
        public async Task<LoginResponse> HandleAsync(LoginRequest request)
        {
            if (request == null)
                return new LoginResponse(false) { ErrorMessage = "No data was received in the request" };

            if (string.IsNullOrEmpty(request.EmailAddress))
                return new LoginResponse(false) { ErrorMessage = "Email Address must have a value" };

            if (string.IsNullOrEmpty(request.Password))
                return new LoginResponse(false) { ErrorMessage = "Password must have a value" };

            if (request.Password.Length < AppConfiguration.PasswordMinimumLength)
                return new LoginResponse(false) { ErrorMessage = $"Invalid password. Password must be at least {AppConfiguration.PasswordMinimumLength} characters" };

            string lowercaseEmail = request.EmailAddress.ToLower().Trim();

            var primaryAccountByEmail = await Repository.LoadPrimaryAccountByEmailAddressAsync(lowercaseEmail);

            if (primaryAccountByEmail == null)
                return new LoginResponse(false) { ErrorMessage = "Login failed. Either no account exists or it is configured incorrectly" };

            if (primaryAccountByEmail.FailedLoginCount > 5)
                return new LoginResponse(false) { ErrorMessage = "Login failed. Account has been locked out due to too many failed logins." };

            if (!Encryptor.PlainTextMatchesHash(request.Password, primaryAccountByEmail.Password))
            {
                await Repository.UpdateFailedLoginCountAsync(primaryAccountByEmail._id, primaryAccountByEmail.FailedLoginCount + 1);
                return new LoginResponse(false) { ErrorMessage = "Invalid login credentials" };
            }

            string userKey = KeyDeriver.DeriveKeyFromPassword(request.Password);
            byte[] encryptionKeyBytes = Encoding.UTF8.GetBytes(userKey);
            string token = TokenGenerator.GenerateToken();
            DateTimeOffset oneHourFromNow = DateTimeOffset.UtcNow.AddMinutes(60);

            var encryptedToken = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, token);
            var encrtypedTokenExpiration = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, oneHourFromNow.ToString());

            await Repository.LoginAsync(primaryAccountByEmail._id, encryptedToken, encrtypedTokenExpiration);
  
            return new LoginResponse(true) { 
                Id = primaryAccountByEmail._id.ToString(), 
                //Username = primaryAccountByEmail.Username, 
                UserKey = userKey, 
                Token = token,
                TokenExpiration = oneHourFromNow
                //ExpiresIn = (int)TimeSpan.FromHours(1).TotalSeconds - 30
            };
        }
    }
}
