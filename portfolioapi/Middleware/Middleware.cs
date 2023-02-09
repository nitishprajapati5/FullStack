using portfolio.Services;

namespace portfolioapi
{
    public class Middleware
    {
        private readonly RequestDelegate _next;

        public Middleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context,RequestProcessor requestProcessor)
        {
            await requestProcessor.ProcessRequest(_next);
        }
    }
}
