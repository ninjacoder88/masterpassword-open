using MasterPassword.DataAccess.MongoDbAtlas;
using System;
using System.Text;
using System.Threading.Tasks;

namespace MasterPassword.BusinessLogic.RequestHandlers.RefreshSession
{
    public interface IRefreshSessionRequestHandler
    {
        Task<RefreshSessionResponse> HandleAsync(RefreshSessionRequest request);
    }

    internal sealed class RefreshSessionRequestHandler(IMongoDbRepository Repository, IEncryptor Encryptor, ITokenGenerator TokenGenerator) : IRefreshSessionRequestHandler
    {
        public async Task<RefreshSessionResponse> HandleAsync(RefreshSessionRequest request)
        {
            string userKey = request.UserKey;
            byte[] encryptionKeyBytes = Encoding.UTF8.GetBytes(userKey);
            string token = TokenGenerator.GenerateToken();
            DateTimeOffset oneHourFromNow = DateTimeOffset.UtcNow.AddMinutes(60);

            var encryptedToken = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, token);
            var encrtypedTokenExpiration = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, oneHourFromNow.ToString());

            await Repository.RefreshTokenAsync(request.UserId, encryptedToken, encrtypedTokenExpiration);
            return new RefreshSessionResponse(true) { Token = token, TokenExpiration = oneHourFromNow };
        }
    }
}
