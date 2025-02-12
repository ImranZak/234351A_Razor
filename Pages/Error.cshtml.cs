using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.Extensions.Logging;

namespace _234351A_Razor.Pages
{
    public class ErrorModel : PageModel
    {
        private readonly ILogger<ErrorModel> _logger;

        public string ErrorMessage { get; private set; } = "An unexpected error occurred.";

        public ErrorModel(ILogger<ErrorModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            var exceptionHandlerPathFeature = HttpContext.Features.Get<IExceptionHandlerPathFeature>();
            if (exceptionHandlerPathFeature != null)
            {
                ErrorMessage = exceptionHandlerPathFeature.Error.Message;
                _logger.LogError(exceptionHandlerPathFeature.Error, "An error occurred while processing the request.");
            }
        }
    }
}
