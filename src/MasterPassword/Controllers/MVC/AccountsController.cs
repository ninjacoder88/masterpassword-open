using MasterPassword.Extension;
using Microsoft.AspNetCore.Mvc;

namespace MasterPassword.Controllers
{
    public class AccountsController : Controller
    {
        [HttpGet]
        public IActionResult Index()
        {
            //if (!HttpContext.IsLoggedIn())
            //{
            //    return RedirectToAction("Index", "Home");
            //}
            return View(new AccountsModel() { Username = ""});
        }
    }

    public class AccountsModel
    {
        public string Username { get; set; }
    }
}
