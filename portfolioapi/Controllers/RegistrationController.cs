using Microsoft.AspNetCore.Mvc;

namespace portfolioapi.Controllers
{
    [ApiController]
    public class RegistrationController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
