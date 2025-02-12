﻿using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using _234351A_Razor.Models;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Linq;
using Microsoft.EntityFrameworkCore;

namespace _234351A_Razor.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(SignInManager<ApplicationUser> signInManager,
                          UserManager<ApplicationUser> userManager,
                          IConfiguration configuration,
                          ILogger<LoginModel> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _configuration = configuration;
            _logger = logger;
        }

        [BindProperty]
        public LoginViewModel LModel { get; set; } = new();

        public class LoginViewModel
        {
            [Required]
            [EmailAddress(ErrorMessage = "Invalid email format.")]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            public bool RememberMe { get; set; }

            public string RecaptchaToken { get; set; }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Model validation failed.");
                return Page();
            }

            _logger.LogInformation("User attempting login: {Email}", LModel.Email);

            // Fix: Ensure reCAPTCHA Token is Provided
            if (string.IsNullOrEmpty(LModel.RecaptchaToken))
            {
                _logger.LogWarning("Captcha verification failed. No token received.");
                ModelState.AddModelError("", "Captcha verification failed. No token received.");
                return Page();
            }

            // Verify Google reCAPTCHA
            string recaptchaSecretKey = _configuration["GoogleReCaptcha:SecretKey"];
            if (string.IsNullOrEmpty(recaptchaSecretKey))
            {
                _logger.LogError("Recaptcha secret key is missing in configuration.");
                ModelState.AddModelError("", "Recaptcha configuration is missing.");
                return Page();
            }

            using var httpClient = new HttpClient();
            var postData = new Dictionary<string, string>
            {
                { "secret", recaptchaSecretKey },
                { "response", LModel.RecaptchaToken }
            };

            var content = new FormUrlEncodedContent(postData);
            var recaptchaResponse = await httpClient.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
            var jsonResponse = await recaptchaResponse.Content.ReadAsStringAsync();

            _logger.LogInformation("Google reCAPTCHA API Response: {Response}", jsonResponse);

            var recaptchaResult = JsonSerializer.Deserialize<RecaptchaResponse>(jsonResponse);
            if (recaptchaResult == null || !recaptchaResult.success)
            {
                _logger.LogWarning("reCAPTCHA failed: {Errors}", recaptchaResult?.error_codes);
                ModelState.AddModelError("", "Captcha verification failed.");
                return Page();
            }

            // Fix: Normalize email (case-insensitive login)
            string normalizedEmail = LModel.Email.Trim().ToUpper();

            // Fix: Find user using normalized email
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail);
            if (user == null)
            {
                _logger.LogWarning("Login failed: User not found. Email: {Email}", normalizedEmail);
                ModelState.AddModelError("", "Invalid login attempt.");
                return Page();
            }

            _logger.LogInformation("User found in database: {Email}", user.Email);

            // Fix: Debug password hashing
            bool passwordCheck = await _userManager.CheckPasswordAsync(user, LModel.Password);
            _logger.LogInformation("Password Check Result: {Result}", passwordCheck);

            if (!passwordCheck)
            {
                _logger.LogWarning("Password mismatch for user: {Email}", normalizedEmail);
                ModelState.AddModelError("", "Invalid login attempt.");
                return Page();
            }

            // Attempt login
            var result = await _signInManager.PasswordSignInAsync(user, LModel.Password, LModel.RememberMe, lockoutOnFailure: true);

            _logger.LogInformation("Sign-in result: Succeeded={Succeeded}, LockedOut={LockedOut}, RequiresTwoFactor={RequiresTwoFactor}",
                result.Succeeded, result.IsLockedOut, result.RequiresTwoFactor);

            if (result.Succeeded)
            {
                return RedirectToPage("/Index");
            }
            else if (result.IsLockedOut)
            {
                _logger.LogWarning("Account locked: {Email}", normalizedEmail);
                ModelState.AddModelError("", "Account locked due to multiple failed attempts. Try again later.");
                return Page();
            }
            else
            {
                _logger.LogWarning("Invalid login attempt for user: {Email}", normalizedEmail);
                ModelState.AddModelError("", "Invalid login attempt.");
                return Page();
            }
        }

        public class RecaptchaResponse
        {
            public bool success { get; set; }
            public double score { get; set; }
            public string action { get; set; }
            public string challenge_ts { get; set; }
            public string hostname { get; set; }
            public List<string> error_codes { get; set; }
        }
    }
}
