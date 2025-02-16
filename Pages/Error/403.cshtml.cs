using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace _234351A_Razor.Pages.Error
{
    public class Error403Model : PageModel
    {
        private readonly ILogger<Error403Model> _logger;

        public Error403Model(ILogger<Error403Model> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            _logger.LogWarning("403 - Forbidden access attempt");
        }
    }
}
