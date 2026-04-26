using MasterPassword.BusinessLogic.RequestHandlers.UpdateFavicon;
using MasterPassword.Models;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace MasterPassword.Controllers.API.v1
{
    [Route("api/[controller]")]
    [ApiController]
    public class FaviconsController(IUpdateFaviconRequestHandler UpdateFaviconRequestHandler) : ControllerBase
    {
        [HttpGet]
        public async Task<IActionResult> Get() => await ActionHandler.HandleAsync(async () =>
            await UpdateFaviconRequestHandler.HandleAsync(new UpdateFaviconRequest()));
    }

    public static class ActionHandler
    {
        public async static Task<IActionResult> HandleAsync<T>(Func<Task<T>> func)
        {
            try
            {
                return new JsonResult(await func());
            }
            catch(Exception ex)
            {
                return new JsonResult(new ExceptionResponse(ex.Message));
            }
        }

        public static IActionResult Handle<T>(Func<T> func)
        {
            try
            {
                return new JsonResult(func());
            }
            catch (Exception ex)
            {
                return new JsonResult(new ExceptionResponse(ex.Message));
            }
        }
    }
}
