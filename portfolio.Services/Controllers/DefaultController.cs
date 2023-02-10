using Microsoft.AspNetCore.Http;
using portfolio.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace portfolio.Services
{
    public class DefaultController
    {
        public readonly AppConfig _appConfig;
        public readonly StaticService _staticService;
        public readonly IHttpContextAccessor _httpContextAccessor;

        public DefaultController(StaticService staticService,IHttpContextAccessor httpContextAccessor)
        {
            _staticService = staticService;
            _appConfig = _staticService.GetAppConfig();
            _httpContextAccessor = httpContextAccessor;
        }
    }
}
