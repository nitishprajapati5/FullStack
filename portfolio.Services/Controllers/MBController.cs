using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace portfolio.Services
{
    public class MBController:DefaultController
    {
        public MBController(StaticService staticService,IHttpContextAccessor httpContextAccessor):base(staticService,httpContextAccessor)
        {

        }
    }
}
