using MasterPassword.BusinessLogic.CreateNote;
using MasterPassword.BusinessLogic.UpdateNote;
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
    public class NotesController(ICreateNoteRequestHandler CreateNoteRequestHandler, IUpdateNoteRequestHandler UpdateNoteRequestHandler) 
        : ControllerBase
    {
        [HttpPost]
        public async Task<IActionResult> CreateNote([FromBody] CreateNoteRequest request) =>
            await ActionHandler.HandleAsync(async () =>
            {
                request.PrimaryAccountId = HttpContext.GetUserId();
                request.UserKey = HttpContext.GetUserKey();
                return await CreateNoteRequestHandler.HandleAsync(request);
            });

        [HttpPatch("{id}")]
        public async Task<IActionResult> UpdateNote([FromBody] UpdateNoteRequest request) =>
            await ActionHandler.HandleAsync(async () =>
            {
                request.PrimaryAccountId = HttpContext.GetUserId();
                request.UserKey = HttpContext.GetUserKey();
                return await UpdateNoteRequestHandler.HandleAsync(request);
            });
    }
}
