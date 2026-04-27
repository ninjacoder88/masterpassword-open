using System.Threading.Tasks;

namespace MasterPassword.BusinessLogic.RequestHandlers.GetSession
{
    public interface IGetSessionRequestHandler
    {
        Task<GetSessionResponse> HandleAsync(GetSessionRequest request);
    }

    internal sealed class GetSessionRequestHandler : IGetSessionRequestHandler
    {
        public async Task<GetSessionResponse> HandleAsync(GetSessionRequest request)
        {
            await Task.CompletedTask;
            return new GetSessionResponse(true);
            //Repository.LoadPrimaryAccountByUsernameAsync();
        }
    }

    public sealed class GetSessionRequest
    {

    }

    public sealed class GetSessionResponse : AppResponse
    {
        public GetSessionResponse(bool success) 
            : base(success)
        {
        }

        public int ExpiresIn { get; set; }
    }
}
