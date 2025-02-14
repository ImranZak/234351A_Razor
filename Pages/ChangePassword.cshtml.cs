using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using _234351A_Razor.Models;
using System.Threading.Tasks;
using System.Linq;
using System;
using _234351A_Razor.Data;
using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication;

namespace _234351A_Razor.Pages
{
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AuthDbContext _context;
        private readonly ILogger<ChangePasswordModel> _logger;

        private const int MaxPasswordAgeMinutes = 30; // Force password change after 30 mins
        private const int MinPasswordChangeIntervalMinutes = 1; // Allow immediate retry after failed attempt

        public ChangePasswordModel(UserManager<ApplicationUser> userManager,
                                   SignInManager<ApplicationUser> signInManager,
                                   AuthDbContext context,
                                   ILogger<ChangePasswordModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
            _logger = logger;
        }

        [BindProperty]
        public ChangePasswordViewModel CModel { get; set; } = new();

        public class ChangePasswordViewModel
        {
            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Current Password")]
            public string CurrentPassword { get; set; }

            [Required]
            [MinLength(12, ErrorMessage = "Password must be at least 12 characters.")]
            [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$",
                ErrorMessage = "Password must contain uppercase, lowercase, number, and special character.")]
            [DataType(DataType.Password)]
            [Display(Name = "New Password")]
            public string NewPassword { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Confirm New Password")]
            [Compare("NewPassword", ErrorMessage = "Passwords do not match.")]
            public string ConfirmPassword { get; set; }
        }

        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {
            _logger.LogInformation("ChangePassword POST request received.");

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("ModelState is invalid. Errors: {Errors}",
                    string.Join(", ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage)));
                return Page(); // Stay on the page to show validation errors
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                _logger.LogWarning("User not found. Redirecting to login.");
                return RedirectToPage("/Login");
            }

            _logger.LogInformation("Validating password change for user {UserEmail}", user.Email);

            // 🚀 Enforce Minimum Password Change Interval
            var lastPasswordChange = user.PasswordChangedAt ?? DateTime.MinValue;
            if ((DateTime.UtcNow - lastPasswordChange).TotalMinutes < MinPasswordChangeIntervalMinutes)
            {
                ModelState.AddModelError("", $"You must wait at least {MinPasswordChangeIntervalMinutes} minutes before changing your password again.");
                _logger.LogWarning("User {UserEmail} attempted to change password too soon.", user.Email);
                return Page();
            }

            // 🚀 Verify Current Password
            var checkPassword = await _userManager.CheckPasswordAsync(user, CModel.CurrentPassword);
            if (!checkPassword)
            {
                ModelState.AddModelError("", "Current password is incorrect.");
                _logger.LogWarning("Invalid current password for user {UserEmail}", user.Email);
                return Page();
            }

            // 🚀 Prevent Password Reuse (Check last 2 passwords)
            var previousPasswords = await _context.PasswordHistories
                .Where(p => p.UserId == user.Id)
                .OrderByDescending(p => p.CreatedAt)
                .Take(2) // Check last 2 passwords
                .ToListAsync();

            foreach (var oldPassword in previousPasswords)
            {
                var result = _userManager.PasswordHasher.VerifyHashedPassword(user, oldPassword.HashedPassword, CModel.NewPassword);
                if (result == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError("", "You cannot reuse your last 2 passwords.");
                    _logger.LogWarning("User {UserEmail} attempted to reuse an old password", user.Email);
                    return Page();
                }
            }

            _logger.LogInformation("Updating password for user {UserEmail}", user.Email);

            // 🚀 Change the Password
            var changeResult = await _userManager.ChangePasswordAsync(user, CModel.CurrentPassword, CModel.NewPassword);
            if (!changeResult.Succeeded)
            {
                foreach (var error in changeResult.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                    _logger.LogWarning("Password change failed for user {UserEmail}: {Error}", user.Email, error.Description);
                }
                return Page();
            }

            _logger.LogInformation("Password changed successfully for user {UserEmail}", user.Email);

            // 🚀 Update Password History
            _context.PasswordHistories.Add(new PasswordHistory
            {
                UserId = user.Id,
                HashedPassword = _userManager.PasswordHasher.HashPassword(user, CModel.NewPassword),
                CreatedAt = DateTime.UtcNow
            });

            if (previousPasswords.Count >= 2)
            {
                _context.PasswordHistories.Remove(previousPasswords.Last()); // Keep only the last 2 passwords
            }

            // 🚀 Update Security Stamp to force re-authentication
            await _userManager.UpdateSecurityStampAsync(user);

            // 🚀 Ensure password change time is updated
            user.PasswordChangedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);
            await _context.SaveChangesAsync();

            // 🚀 Logout the user after password change
            TempData["SuccessMessage"] = "Password changed successfully! Please log in again.";
            await _signInManager.SignOutAsync();
            HttpContext.SignOutAsync();

            return RedirectToPage("/Login");
        }

    }
}
