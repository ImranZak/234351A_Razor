using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Diagnostics;

namespace _234351A_Razor.Pages
{
    public class ErrorModel : PageModel
    {
        public string ErrorMessage { get; private set; }

        public void OnGet()
        {
            var exceptionHandlerPathFeature = HttpContext.Features.Get<IExceptionHandlerPathFeature>();
            if (exceptionHandlerPathFeature != null)
            {
                ErrorMessage = "An unexpected error occurred.";
            }
        }
    }
}
