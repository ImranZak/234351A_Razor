using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using _234351A_Razor.Models;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Web;

namespace _234351A_Razor.Pages
{
    public class ConfirmEmailModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<ConfirmEmailModel> _logger;

        public ConfirmEmailModel(UserManager<ApplicationUser> userManager, ILogger<ConfirmEmailModel> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        [BindProperty]
        public string Message { get; set; }

        public async Task<IActionResult> OnGetAsync(string userId, string token)
        {
            _logger.LogInformation("Received Confirmation Request - UserID: {UserID}, Token: {Token}", userId, token);

            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("Invalid email confirmation request: Missing user ID or token.");
                Message = "Invalid email confirmation link.";
                return Page();
            }
            // Encode inputs before displaying
            userId = HttpUtility.HtmlEncode(userId);
            token = HttpUtility.HtmlEncode(token);

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("Invalid email confirmation request: User not found.");
                Message = "Invalid email confirmation link.";
                return Page();
            }

            try
            {
                // Decode the token before confirming the email
                var decodedTokenBytes = WebEncoders.Base64UrlDecode(token);
                var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);
                _logger.LogInformation("Decoded Token: {DecodedToken}", decodedToken);

                var result = await _userManager.ConfirmEmailAsync(user, decodedToken);

                if (result.Succeeded)
                {
                    _logger.LogInformation("User {Email} confirmed their email successfully.", user.Email);
                    Message = "Email confirmed successfully. You can now log in.";
                }
                else
                {
                    _logger.LogWarning("Email confirmation failed for user: {Email}", user.Email);
                    Message = "Email confirmation failed. The link may have expired or is invalid.";
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Error decoding email confirmation token: {Error}", ex.Message);
                Message = "Invalid email confirmation link.";
            }

            return Page();
        }
    }
}
