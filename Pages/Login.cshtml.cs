using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using _234351A_Razor.Models;

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
        public LoginViewModel LModel { get; set; }

        public class LoginViewModel
        {
            [Required] public string Email { get; set; }
            [Required][DataType(DataType.Password)] public string Password { get; set; }
            public bool RememberMe { get; set; }
            public string RecaptchaToken { get; set; }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // Verify Google reCAPTCHA
            var httpClient = new HttpClient();
            var response = await httpClient.PostAsync(
                $"https://www.google.com/recaptcha/api/siteverify?secret=6LdTW9IqAAAAACxuDiS8O9i_XIvlueaPncuQIfz2&response={LModel.RecaptchaToken}",
                null
            );
            var jsonResponse = await response.Content.ReadAsStringAsync();
            var recaptchaResult = JsonSerializer.Deserialize<RecaptchaResponse>(jsonResponse);

            if (!recaptchaResult.success)
            {
                ModelState.AddModelError("", "Captcha verification failed.");
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(LModel.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "Invalid login attempt.");
                return Page();
            }

            var result = await _signInManager.PasswordSignInAsync(user, LModel.Password, LModel.RememberMe, lockoutOnFailure: true);
            if (result.Succeeded)
            {
                return RedirectToPage("Index");
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
    }
}
