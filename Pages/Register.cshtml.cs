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
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using Microsoft.Extensions.Configuration;
using System.Net.Mail;
using System.Text.Encodings.Web;

namespace _234351A_Razor.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IDataProtector _protector;
        private readonly IWebHostEnvironment _environment;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IConfiguration _configuration;

        public RegisterModel(UserManager<ApplicationUser> userManager,
                             IDataProtectionProvider provider,
                             IWebHostEnvironment environment,
                             ILogger<RegisterModel> logger,
                             IConfiguration configuration)
        {
            _userManager = userManager;
            _protector = provider.CreateProtector("CreditCardProtector");
            _environment = environment;
            _logger = logger;
            _configuration = configuration;
        }

        [BindProperty]
        public RegisterViewModel RModel { get; set; } = new();

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

            public string? RecaptchaToken { get; set; }
            public IFormFile PhotoFile { get; set; }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            _logger.LogInformation("Received reCAPTCHA token: {Token}", RModel.RecaptchaToken);

            if (string.IsNullOrEmpty(RModel.RecaptchaToken))
            {
                ModelState.AddModelError("", "Captcha verification failed. No token received.");
                return Page();
            }

            // Verify Google reCAPTCHA using secret key from appsettings.json
            string recaptchaSecretKey = _configuration["GoogleReCaptcha:SecretKey"];
            using var httpClient = new HttpClient();
            var postData = new Dictionary<string, string>
            {
                { "secret", recaptchaSecretKey },
                { "response", RModel.RecaptchaToken }
            };

            var content = new FormUrlEncodedContent(postData);
            var recaptchaResponse = await httpClient.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
            var jsonResponse = await recaptchaResponse.Content.ReadAsStringAsync();
            var recaptchaResult = JsonSerializer.Deserialize<RecaptchaResponse>(jsonResponse);

            if (recaptchaResult == null || !recaptchaResult.success)
            {
                ModelState.AddModelError("", "Captcha verification failed. Please try again.");
                return Page();
            }

            var existingUser = await _userManager.FindByEmailAsync(RModel.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("", "Email is already in use.");
                return Page();
            }

            RModel.FirstName = HttpUtility.HtmlEncode(RModel.FirstName);
            RModel.LastName = HttpUtility.HtmlEncode(RModel.LastName);
            RModel.BillingAddress = HttpUtility.HtmlEncode(RModel.BillingAddress);
            RModel.ShippingAddress = HttpUtility.HtmlEncode(RModel.ShippingAddress);
            string encryptedCreditCard = _protector.Protect(RModel.CreditCard);

            string photoPath = null;
            if (RModel.PhotoFile != null)
            {
                string uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads");
                Directory.CreateDirectory(uploadsFolder);
                string uniqueFileName = $"{Guid.NewGuid()}{Path.GetExtension(RModel.PhotoFile.FileName)}";
                photoPath = Path.Combine("uploads", uniqueFileName);

                using var fileStream = new FileStream(Path.Combine(uploadsFolder, uniqueFileName), FileMode.Create);
                await RModel.PhotoFile.CopyToAsync(fileStream);
            }

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
                PhotoPath = photoPath,
                EmailConfirmed = false // Default to not confirmed
            };

            var result = await _userManager.CreateAsync(user, RModel.Password);

            if (result.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
                var confirmationLink = Url.Page("/ConfirmEmail",
                                                pageHandler: null,
                                                values: new { userId = user.Id, token = encodedToken },
                                                protocol: Request.Scheme);

                SendEmail(user.Email, "Confirm Your Email", $"Click here to confirm your email: <a href='{HtmlEncoder.Default.Encode(confirmationLink)}'>Confirm Email</a>");

                return RedirectToPage("/CheckEmail");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }

            return Page();
        }

        private void SendEmail(string toEmail, string subject, string body)
        {
            var smtpClient = new SmtpClient(_configuration["EmailSettings:SmtpServer"])
            {
                Port = int.Parse(_configuration["EmailSettings:Port"]),
                Credentials = new System.Net.NetworkCredential(
                    _configuration["EmailSettings:Username"],
                    _configuration["EmailSettings:Password"]),
                EnableSsl = true,
            };

            smtpClient.Send(new MailMessage
            {
                From = new MailAddress(_configuration["EmailSettings:SenderEmail"]),
                Subject = subject,
                Body = body,
                IsBodyHtml = true,
                To = { toEmail }
            });
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
