using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;
using _234351A_Razor.Models;
using Microsoft.Extensions.Logging;

namespace _234351A_Razor.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<LogoutModel> _logger;

        public LogoutModel(SignInManager<ApplicationUser> signInManager,
                           UserManager<ApplicationUser> userManager,
                           ILogger<LogoutModel> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                user.SecurityStamp = Guid.NewGuid().ToString(); // Invalidate session
                await _userManager.UpdateAsync(user);
            }

            _logger.LogInformation("User logged out: {Email}", user?.Email);

            await _signInManager.SignOutAsync();
            HttpContext.Session.Clear(); // Destroy session data
            Response.Cookies.Delete(".AspNetCore.Session"); // Ensure session cookie is deleted

            return RedirectToPage("/Login", new { Message = "You have been logged out." });
        }
    }
}
