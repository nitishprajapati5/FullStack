using Microsoft.AspNetCore.Mvc;
using portfolio.Services;

namespace portfolioapi.Controllers
{
    [Produces("application/json")]
    [Route("MB/Default")]
    public class DefaultController :MBController
    {
        public DefaultController(StaticService staticService,IHttpContextAccessor httpContextAccessor)
                    :base(staticService,httpContextAccessor)
        {

        }
    }
}
