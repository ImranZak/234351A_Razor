using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace _234351A_Razor.Pages.Error
{
    public class Error500Model : PageModel
    {
        private readonly ILogger<Error500Model> _logger;

        public Error500Model(ILogger<Error500Model> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            _logger.LogError("500 - Internal Server Error encountered");
        }
    }
}
