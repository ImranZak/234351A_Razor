using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using _234351A_Razor.Models;
using System.ComponentModel.DataAnnotations;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using System.Threading.Tasks;

namespace _234351A_Razor.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<ResetPasswordModel> _logger;

        public ResetPasswordModel(UserManager<ApplicationUser> userManager, ILogger<ResetPasswordModel> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        [BindProperty]
        public ResetPasswordViewModel RModel { get; set; } = new();

        public class ResetPasswordViewModel
        {
            [Required]
            public string UserId { get; set; }

            [Required]
            public string Token { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [MinLength(12, ErrorMessage = "Password must be at least 12 characters.")]
            [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$",
                ErrorMessage = "Password must contain uppercase, lowercase, number, and special character.")]
            public string NewPassword { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [Compare("NewPassword", ErrorMessage = "Passwords do not match.")]
            public string ConfirmPassword { get; set; }
        }

        public IActionResult OnGet(string userId, string token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("Invalid password reset request: Missing userId or token.");
                return BadRequest("Invalid password reset request.");
            }

            _logger.LogInformation("Password reset page accessed for User ID: {UserId}", userId);
            RModel.UserId = userId;
            RModel.Token = token;
            return Page();
        }

        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("ModelState is invalid for password reset. Errors: {Errors}",
                    string.Join(", ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage)));
                return Page();
            }

            var user = await _userManager.FindByIdAsync(RModel.UserId);
            if (user == null)
            {
                _logger.LogWarning("Password reset attempted for non-existent user: {UserId}", RModel.UserId);
                return RedirectToPage("/ResetPasswordConfirmation");
            }

            _logger.LogInformation("Resetting password for user {UserEmail}", user.Email);

            try
            {
                var decodedTokenBytes = WebEncoders.Base64UrlDecode(RModel.Token);
                var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

                var result = await _userManager.ResetPasswordAsync(user, decodedToken, RModel.NewPassword);
                if (result.Succeeded)
                {
                    _logger.LogInformation("Password successfully reset for user {UserEmail}", user.Email);
                    return RedirectToPage("/ResetPasswordConfirmation");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                    _logger.LogWarning("Password reset failed for {UserEmail}: {Error}", user.Email, error.Description);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Error decoding password reset token: {ErrorMessage}", ex.Message);
                ModelState.AddModelError("", "Invalid reset link. Please request a new password reset.");
            }

            return Page();
        }
    }
}
