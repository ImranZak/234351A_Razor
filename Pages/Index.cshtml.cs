using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.DataProtection;
using _234351A_Razor.Models;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace _234351A_Razor.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IDataProtector _protector;

        public IndexModel(ILogger<IndexModel> logger,
                          UserManager<ApplicationUser> userManager,
                          SignInManager<ApplicationUser> signInManager,
                          IDataProtectionProvider provider)
        {
            _logger = logger;
            _userManager = userManager;
            _signInManager = signInManager;
            _protector = provider.CreateProtector("CreditCardProtector");
        }

        public ApplicationUser CurrentUser { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            // Validate session token
            string storedToken = HttpContext.Session.GetString("AuthToken");
            if (string.IsNullOrEmpty(storedToken) || storedToken != user.SecurityStamp)
            {
                _logger.LogWarning("Invalid session detected for user: {Email}", user.Email);
                await _signInManager.SignOutAsync();
                HttpContext.Session.Clear();
                Response.Cookies.Delete(".AspNetCore.Session");
                return RedirectToPage("/Login", new { Message = "Session expired or invalid. Please log in again." });
            }

            // Decrypt sensitive data
            try
            {
                user.CreditCard = _protector.Unprotect(user.CreditCard);
            }
            catch
            {
                _logger.LogError("Failed to decrypt Credit Card for user: {User}", user.Email);
                user.CreditCard = "Error decrypting data";
            }

            CurrentUser = user;
            return Page();
        }
    }
}
