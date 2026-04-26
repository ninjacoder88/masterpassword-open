using MasterPassword.BusinessLogic.RequestHandlers.GetSession;
using MasterPassword.BusinessLogic.RequestHandlers.RefreshSession;
using MasterPassword.Extension;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace MasterPassword.Controllers.API.v1
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class SessionController(IRefreshSessionRequestHandler RefreshSessionRequestHandler) : ControllerBase
    {
        [HttpGet]
        public IActionResult Get() =>
            ActionHandler.Handle(() =>
            {
                DateTimeOffset tokenExpiration = HttpContext.GetTokenExpiration();
                TimeSpan offset = tokenExpiration - DateTimeOffset.UtcNow;
                return new GetSessionResponse(true) { ExpiresIn = (int)offset.TotalSeconds };
            });

        [HttpGet("Refresh")]
        public async Task<IActionResult> RefeshSession() =>
            await ActionHandler.HandleAsync(async () =>
            {
                string userId = HttpContext.GetUserId();
                RefreshSessionResponse response = await RefreshSessionRequestHandler.HandleAsync(new RefreshSessionRequest() { UserId = userId, UserKey = HttpContext.GetUserKey() });
                HttpContext.Refresh(userId, response.TokenExpiration);
                return response;
            });
    }
}
