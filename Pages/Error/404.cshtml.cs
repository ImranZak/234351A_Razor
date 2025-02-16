using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace _234351A_Razor.Pages.Error
{
    public class Error404Model : PageModel
    {
        private readonly ILogger<Error404Model> _logger;

        public Error404Model(ILogger<Error404Model> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            _logger.LogWarning("404 - Page not found");
        }
    }
}
