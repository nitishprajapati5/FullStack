using Microsoft.AspNetCore.Mvc;
using portfolio.Models.Tables;
using portfolio.Services;
using portfolio.Shared.Leap.Models;
using static portfolio.Models.Response.MiscellenousResponse;

namespace portfolioapi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AppStartsController : DefaultController
    {
        
       public AppStartsController(StaticService staticService,IHttpContextAccessor httpContextAccessor):base(staticService,httpContextAccessor)
        {

        }


       [Route("registrationDropDown"), HttpGet]
        public async Task<ResJsonOutput> registrationDropDown()
        {
            ResJsonOutput res = new ResJsonOutput();
            try
            {
                GroupDetails groupDetails = new GroupDetails();
                groupDetails = await _staticService.ServiceRepository<GroupDetails>().GetSingle(o => o.Id == 1);
                 
            }
            catch (Exception ex)
            {

            }

            return res;
        }


    }
}
