using MasterPassword.BusinessLogic.CreatePrimaryAccount;
using MasterPassword.BusinessLogic.LoadSecondaryAccounts;
using MasterPassword.BusinessLogic.Login;
using MasterPassword.BusinessLogic.RequestHandlers.Logout;
using MasterPassword.Extension;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace MasterPassword.Controllers.API.v1
{
    [Route("api/[controller]")]
    [ApiController]
    public class PrimaryAccountsController(ILoginRequestHandler LoginRequestHandler, 
        ICreatePrimaryAccountRequestHandler CreatePrimaryAccountRequestHandler,
            ILoadShallowSecondaryAccountsRequestHandler LoadShallowSecondaryAccountsRequestHandler,
            ILogoutRequestHandler LogoutRequestHandler) : ControllerBase
    {
        [HttpPost]
        public async Task<IActionResult> CreatePrimaryAccount([FromBody] CreatePrimaryAccountRequest request) =>
            await ActionHandler.HandleAsync(async () => await CreatePrimaryAccountRequestHandler.HandleAsync(request));

        [HttpGet("SecondaryAccounts")]
        [Authorize]
        public async Task<IActionResult> LoadShallowSecondaryAccounts() =>
            await ActionHandler.HandleAsync(async () =>
            {
                return await LoadShallowSecondaryAccountsRequestHandler.HandleAsync(new LoadShallowSecondaryAccountsRequest
                {
                    PrimaryAccountId = HttpContext.GetUserId(),
                    UserKey = HttpContext.GetUserKey()
                });
            });

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request) =>
            await ActionHandler.HandleAsync(async () =>
            {
                LoginResponse response = await LoginRequestHandler.HandleAsync(request);

                if (response.Success == true)
                    HttpContext.Login(response.Id, response.UserKey, response.TokenExpiration);

                response.UserKey = string.Empty;
                return response;
            });

        [HttpGet("Logout")]
        public async Task<IActionResult> Logout() =>
            await ActionHandler.HandleAsync(async () =>
            {
                LogoutResponse response = await LogoutRequestHandler.HandleAsync(new LogoutRequest() { Id = HttpContext.GetUserId() });
                HttpContext.Logout();
                return response;
            });
    }
}
