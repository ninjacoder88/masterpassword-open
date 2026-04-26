using MasterPassword.BusinessLogic.CreateSecondaryAccount;
using MasterPassword.BusinessLogic.DeleteSecondaryAccount;
using MasterPassword.BusinessLogic.LoadNotes;
using MasterPassword.BusinessLogic.LoadSecondaryAccount;
using MasterPassword.BusinessLogic.UpdateSecondaryAccount;
using MasterPassword.Extension;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace MasterPassword.Controllers.API.v1
{
    [Route("api/[controller]")]
    [Authorize]
    [ApiController]
    public class SecondaryAccountsController(ICreateSecondaryAccountRequestHandler CreateSecondaryAccountRequestHandler, 
        ILoadSecondaryAccountRequestHandler LoadSecondaryAccountRequestHandler,
            IUpdateSecondaryAccountRequestHandler UpdateSecondaryAccountRequestHandler, ILoadNotesRequestHandler LoadNotesRequestHandler,
            IDeleteSecondaryAccountRequestHandler DeleteSecondaryAccountRequestHandler) : ControllerBase
    {
        [HttpPost]
        public async Task<IActionResult> CreateSecondaryAccount([FromBody] CreateSecondaryAccountRequest request) =>
            await ActionHandler.HandleAsync(async () =>
            {
                request.PrimaryAccountId = HttpContext.GetUserId();
                request.UserKey = HttpContext.GetUserKey();
                return await CreateSecondaryAccountRequestHandler.HandleAsync(request);
            });

        [HttpDelete]
        public async Task<IActionResult> DeleteSecondaryAccount([FromBody] DeleteSecondaryAccountRequest request) =>
            await ActionHandler.HandleAsync(async () =>
            {
                request.PrimaryAccountId = HttpContext.GetUserId();
                request.UserKey = HttpContext.GetUserKey();
                return await DeleteSecondaryAccountRequestHandler.HandleAsync(request);
            });

        [HttpGet("{id}/Notes")]
        public async Task<IActionResult> LoadNotes(string id) =>
            await ActionHandler.HandleAsync(async () =>
            {
                LoadNotesRequest request = new() { PrimaryAccountId = HttpContext.GetUserId(), UserKey = HttpContext.GetUserKey(), SecondaryAccountId = id };
                return await LoadNotesRequestHandler.HandleAsync(request);
            });

        [HttpGet("{id}")]
        public async Task<IActionResult> LoadSecondaryAccount(string id) =>
            await ActionHandler.HandleAsync(async () =>
            {
                LoadSecondaryAccountRequest request = new() { Id = id, PrimaryAccountId = HttpContext.GetUserId(), UserKey = HttpContext.GetUserKey() };
                return await LoadSecondaryAccountRequestHandler.HandleAsync(request);
            });

        [HttpPatch("{id}")]
        public async Task<IActionResult> UpdateSecondaryAccount([FromBody] UpdateSecondaryAccountRequest request) =>
            await ActionHandler.HandleAsync(async () =>
            {
                request.PrimaryAccountId = HttpContext.GetUserId();
                request.UserKey = HttpContext.GetUserKey();
                return await UpdateSecondaryAccountRequestHandler.HandleAsync(request);
            });
    }
}
