using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.DataProtection;
using System.IO;
using System.Threading.Tasks;
using _234351A_Razor.Models;
using System.Net.Http;
using System.Text.Json;
using System.Web;

namespace _234351A_Razor.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IDataProtector _protector;
        private readonly IWebHostEnvironment _environment;

        public RegisterModel(UserManager<ApplicationUser> userManager, IDataProtectionProvider provider, IWebHostEnvironment environment)
        {
            _userManager = userManager;
            _protector = provider.CreateProtector("CreditCardProtector");
            _environment = environment;
        }

        [BindProperty]
        public RegisterViewModel RModel { get; set; }

        public class RegisterViewModel
        {
            [Required]
            [RegularExpression(@"^[a-zA-Z]+$", ErrorMessage = "Only letters allowed.")]
            public string FirstName { get; set; }

            [Required]
            [RegularExpression(@"^[a-zA-Z]+$", ErrorMessage = "Only letters allowed.")]
            public string LastName { get; set; }

            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [MinLength(12, ErrorMessage = "Password must be at least 12 characters.")]
            [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$",
                ErrorMessage = "Password must contain uppercase, lowercase, number, and special character.")]
            public string Password { get; set; }

            [Required]
            [Compare("Password", ErrorMessage = "Passwords do not match.")]
            public string ConfirmPassword { get; set; }

            [Required]
            [RegularExpression(@"^\d{8}$", ErrorMessage = "Mobile number must be 8 digits.")]
            public string MobileNo { get; set; }

            [Required]
            public string BillingAddress { get; set; }

            [Required]
            public string ShippingAddress { get; set; }

            [Required]
            [RegularExpression(@"^\d{16}$", ErrorMessage = "Credit Card number must be 16 digits.")]
            public string CreditCard { get; set; }

            [Required]
            public string RecaptchaToken { get; set; } // Added missing field

            public IFormFile PhotoFile { get; set; } // Image Upload Handling
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Verify Google reCAPTCHA
            var httpClient = new HttpClient();
            var recaptchaResponse = await httpClient.PostAsync(
                $"https://www.google.com/recaptcha/api/siteverify?secret=6LdTW9IqAAAAACxuDiS8O9i_XIvlueaPncuQIfz2&response={RModel.RecaptchaToken}",
                null
            );

            var jsonResponse = await recaptchaResponse.Content.ReadAsStringAsync();
            var recaptchaResult = JsonSerializer.Deserialize<RecaptchaResponse>(jsonResponse);

            if (recaptchaResult == null || !recaptchaResult.success)
            {
                ModelState.AddModelError("", "Captcha verification failed.");
                return Page();
            }

            // Check if email already exists
            var existingUser = await _userManager.FindByEmailAsync(RModel.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("", "Email is already in use.");
                return Page();
            }

            // Sanitize input fields
            RModel.FirstName = HttpUtility.HtmlEncode(RModel.FirstName);
            RModel.LastName = HttpUtility.HtmlEncode(RModel.LastName);
            RModel.BillingAddress = HttpUtility.HtmlEncode(RModel.BillingAddress);
            RModel.ShippingAddress = HttpUtility.HtmlEncode(RModel.ShippingAddress);

            // Encrypt Credit Card
            string encryptedCreditCard = _protector.Protect(RModel.CreditCard);

            // Handle Profile Photo Upload
            string photoPath = null;
            if (RModel.PhotoFile != null)
            {
                var fileExt = Path.GetExtension(RModel.PhotoFile.FileName).ToLower();
                if (fileExt != ".jpg")
                {
                    ModelState.AddModelError("", "Only JPG images are allowed.");
                    return Page();
                }

                string uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads");
                Directory.CreateDirectory(uploadsFolder);
                string uniqueFileName = $"{Guid.NewGuid()}{fileExt}";
                photoPath = Path.Combine("uploads", uniqueFileName);

                using (var fileStream = new FileStream(Path.Combine(uploadsFolder, uniqueFileName), FileMode.Create))
                {
                    await RModel.PhotoFile.CopyToAsync(fileStream);
                }
            }

            // Create User
            var user = new ApplicationUser
            {
                FirstName = RModel.FirstName,
                LastName = RModel.LastName,
                Email = RModel.Email,
                UserName = RModel.Email,
                CreditCard = encryptedCreditCard,
                MobileNo = RModel.MobileNo,
                BillingAddress = RModel.BillingAddress,
                ShippingAddress = RModel.ShippingAddress,
                PhotoPath = photoPath
            };

            var result = await _userManager.CreateAsync(user, RModel.Password);

            if (result.Succeeded)
            {
                return RedirectToPage("/Login");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
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
