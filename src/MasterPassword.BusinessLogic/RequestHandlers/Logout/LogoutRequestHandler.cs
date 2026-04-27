using MasterPassword.DataAccess.MongoDbAtlas;
using System.Threading.Tasks;

namespace MasterPassword.BusinessLogic.RequestHandlers.Logout
{
    public interface ILogoutRequestHandler
    {
        Task<LogoutResponse> HandleAsync(LogoutRequest request);
    }

    internal sealed class LogoutRequestHandler(IMongoDbRepository Repository) : ILogoutRequestHandler
    {
        public async Task<LogoutResponse> HandleAsync(LogoutRequest request)
        {
            await Repository.LogoutAsync(request.Id);
            return new LogoutResponse(true);
        }
    }
}
