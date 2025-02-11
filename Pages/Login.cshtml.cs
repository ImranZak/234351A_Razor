using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using _234351A_Razor.Models;
using System.Collections.Generic;
using Microsoft.AspNetCore.Http;

namespace _234351A_Razor.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
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

            [Required]
            public string RecaptchaToken { get; set; }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Verify Google reCAPTCHA
            using var httpClient = new HttpClient();
            var postData = new Dictionary<string, string>
            {
                { "secret", "6LdTW9IqAAAAACxuDiS8O9i_XIvlueaPncuQIfz2" },
                { "response", LModel.RecaptchaToken }
            };

            var content = new FormUrlEncodedContent(postData);
            var recaptchaResponse = await httpClient.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
            var jsonResponse = await recaptchaResponse.Content.ReadAsStringAsync();
            var recaptchaResult = JsonSerializer.Deserialize<RecaptchaResponse>(jsonResponse);

            if (recaptchaResult == null || !recaptchaResult.success)
            {
                ModelState.AddModelError("", "Captcha verification failed.");
                return Page();
            }

            // Check if user exists
            var user = await _userManager.FindByEmailAsync(LModel.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "Invalid login attempt.");
                return Page();
            }

            // Attempt login
            var result = await _signInManager.PasswordSignInAsync(user, LModel.Password, LModel.RememberMe, lockoutOnFailure: true);
            if (result.Succeeded)
            {
                // Clear previous session to prevent session fixation attacks
                HttpContext.Session.Clear();

                // Generate a new session authentication token
                string authToken = System.Guid.NewGuid().ToString();
                HttpContext.Session.SetString("UserId", user.Id);
                HttpContext.Session.SetString("AuthToken", authToken);

                Response.Cookies.Append("AuthToken", authToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict
                });

                return LocalRedirect(Url.Content("~/"));
            }
            else if (result.IsLockedOut)
            {
                ModelState.AddModelError("", "Account locked due to multiple failed attempts. Try again later.");
            }
            else
            {
                ModelState.AddModelError("", "Invalid login attempt.");
            }

            return Page();
        }

        public class RecaptchaResponse
        {
            public bool success { get; set; }
            public double score { get; set; }
            public string action { get; set; }
            public string challenge_ts { get; set; }
            public string hostname { get; set; }
        }
    }
}
