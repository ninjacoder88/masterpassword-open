using MasterPassword.BusinessLogic.RequestHandlers.Logout;
using MasterPassword.Extension;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace MasterPassword.Controllers
{
    public class HomeController : Controller
    {
        public HomeController(ILogoutRequestHandler logoutRequestHandler)
        {
            _logoutRequestHandler = logoutRequestHandler;
        }

        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Logout()
        {
            _logoutRequestHandler.HandleAsync(new LogoutRequest() { Id = HttpContext.GetUserId() });
            HttpContext.Logout();
            return RedirectToAction("Index");
        }

        private ILogoutRequestHandler _logoutRequestHandler;
    }
}
