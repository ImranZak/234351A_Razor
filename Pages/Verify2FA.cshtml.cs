using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using _234351A_Razor.Models;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System;

namespace _234351A_Razor.Pages
{
    public class Verify2FAModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<Verify2FAModel> _logger;

        public Verify2FAModel(SignInManager<ApplicationUser> signInManager,
                              UserManager<ApplicationUser> userManager,
                              ILogger<Verify2FAModel> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }

        [BindProperty]
        public string Code { get; set; }

        public string UserId { get; set; }

        // GET: Load 2FA Page
        public async Task<IActionResult> OnGetAsync()
        {
            UserId = HttpContext.Session.GetString("UserId");

            if (string.IsNullOrEmpty(UserId))
            {
                _logger.LogWarning("2FA verification failed: Missing session userId.");
                return RedirectToPage("/Login");
            }

            var user = await _userManager.FindByIdAsync(UserId);
            if (user == null)
            {
                _logger.LogWarning("Invalid 2FA request. User not found.");
                return RedirectToPage("/Login");
            }

            _logger.LogInformation("User {Email} is on the 2FA verification page.", user.Email);
            return Page();
        }

        // POST: Verify 2FA Code
        public async Task<IActionResult> OnPostAsync()
        {
            UserId = HttpContext.Session.GetString("UserId");

            if (string.IsNullOrEmpty(UserId))
            {
                _logger.LogWarning("2FA verification failed: Missing session userId.");
                return RedirectToPage("/Login");
            }

            var user = await _userManager.FindByIdAsync(UserId);
            if (user == null)
            {
                _logger.LogWarning("Invalid 2FA verification request. User not found.");
                return RedirectToPage("/Login");
            }

            _logger.LogInformation("Verifying 2FA code for user: {Email}", user.Email);

            // Correct verification method
            bool is2FAValid = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, Code);

            if (!is2FAValid)
            {
                _logger.LogWarning("Invalid 2FA code entered for user: {Email}", user.Email);
                ModelState.AddModelError("", "Invalid 2FA code. Please try again.");
                return Page();
            }

            // Perform sign-in after successful verification
            await _signInManager.SignInAsync(user, isPersistent: false);

            _logger.LogInformation("2FA verification successful for user: {Email}", user.Email);
            Console.WriteLine($"[DEBUG] 2FA Verification Passed for {user.Email}");

            // Remove session token
            HttpContext.Session.Remove("UserId");

            return RedirectToPage("/Index");
        }
    }
}
