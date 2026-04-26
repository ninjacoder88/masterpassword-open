using MasterPassword.BusinessLogic.GeneratePassword;
using Microsoft.AspNetCore.Mvc;

namespace MasterPassword.Controllers.API.v1
{
    [Route("api/[controller]")]
    [ApiController]
    public class PasswordController(IGeneratePasswordRequestHandler GeneratePasswordRequestHandler) : ControllerBase
    {
        [HttpGet]
        public IActionResult Get([FromQuery] int length, [FromQuery] bool upper, [FromQuery] bool number, 
            [FromQuery] bool special, [FromQuery] string? exclude) =>
            ActionHandler.Handle(() =>
            {
                GeneratePasswordRequest request = new()
                {
                    IncludeCapital = upper,
                    IncludeNumbers = number,
                    IncludeSpecial = special,
                    Exclusion = exclude,
                    Length = length
                };

                 return GeneratePasswordRequestHandler.Handle(request);
            });
    }
}
