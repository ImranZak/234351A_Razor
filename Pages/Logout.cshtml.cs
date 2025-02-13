using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;
using _234351A_Razor.Models;
using Microsoft.Extensions.Logging;
using _234351A_Razor.Data;

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
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                // Invalidate all active sessions
                user.SecurityStamp = Guid.NewGuid().ToString();
                await _userManager.UpdateAsync(user);

                // Clear session and cookies
                await _signInManager.SignOutAsync();
                HttpContext.Session.Clear();
                Response.Cookies.Delete(".AspNetCore.Session");

                return RedirectToPage("/Login", new { Message = "You have been logged out." });
            }
            return RedirectToPage("/Index");
        }

        // Audit Logging Method
        private async Task LogAuditEvent(string userEmail, string action)
        {
            var logEntry = new AuditLog
            {
                UserEmail = userEmail,
                Action = action,
                IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            };

            using (var _context = HttpContext.RequestServices.GetService<AuthDbContext>())
            {
                _context.AuditLogs.Add(logEntry);
                await _context.SaveChangesAsync();
            }
        }

    }
}
