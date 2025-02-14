using System.ComponentModel.DataAnnotations;
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
using System.Web;
using System;
using _234351A_Razor.Data;
using System.Net.Mail;
using System.Net;

namespace _234351A_Razor.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<LoginModel> _logger;
        private readonly AuthDbContext _context;

        public LoginModel(SignInManager<ApplicationUser> signInManager,
                          UserManager<ApplicationUser> userManager,
                          IConfiguration configuration,
                          ILogger<LoginModel> logger,
                          AuthDbContext context)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _configuration = configuration;
            _logger = logger;
            _context = context;
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

        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Model validation failed.");
                return Page();
            }

            _logger.LogInformation("User attempting login: {Email}", LModel.Email);

            // Ensure reCAPTCHA Token is Provided
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
            if (recaptchaResult == null || !recaptchaResult.success || recaptchaResult.score < 0.5)
            {
                _logger.LogWarning("reCAPTCHA failed. Score: {Score}, Errors: {Errors}", recaptchaResult?.score, recaptchaResult?.error_codes);
                ModelState.AddModelError("", "Captcha verification failed. Please try again.");
                return Page();
            }

            // Normalize email for case-insensitive login
            string normalizedEmail = LModel.Email.Trim().ToUpper();

            // Find user using normalized email
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail);
            if (user == null)
            {
                _logger.LogWarning("Login failed: User not found. Email: {Email}", normalizedEmail);
                ModelState.AddModelError("", "Invalid login attempt.");
                await LogAuditEvent(normalizedEmail, "Login Failed");
                return Page();
            }

            _logger.LogInformation("User found in database: {Email}", user.Email);

            // Check if the user is locked out before checking the password
            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning("Account locked out: {Email}", normalizedEmail);
                ModelState.AddModelError("", "Your account is locked due to multiple failed attempts. Try again later.");
                await LogAuditEvent(user.Email, "Account Locked Out");
                return Page();
            }

            // Encode email AFTER checking email
            LModel.Email = HttpUtility.HtmlEncode(LModel.Email);

            // Verify password
            bool passwordCheck = await _userManager.CheckPasswordAsync(user, LModel.Password);
            if (!passwordCheck)
            {
                _logger.LogWarning("Password mismatch for user: {Email}", normalizedEmail);
                await _userManager.AccessFailedAsync(user);

                if (await _userManager.IsLockedOutAsync(user))
                {
                    _logger.LogWarning("Account locked due to too many failed attempts: {Email}", normalizedEmail);
                    ModelState.AddModelError("", "Account locked due to multiple failed attempts. Try again later.");
                    await LogAuditEvent(user.Email, "Account Locked Out");
                }
                else
                {
                    ModelState.AddModelError("", "Invalid login attempt.");
                    await LogAuditEvent(user.Email, "Login Failed - Incorrect Password");
                }

                return Page();
            }

            // Reset failed access count on successful login
            await _userManager.ResetAccessFailedCountAsync(user);

            // Log successful login attempt
            await LogAuditEvent(user.Email, "Login Success");

            // Ensure session fixation prevention
            HttpContext.Session.Clear();

            // Check if another session is active
            var existingToken = await _userManager.GetSecurityStampAsync(user);
            if (!string.IsNullOrEmpty(existingToken))
            {
                // Logout the previous session
                await _signInManager.SignOutAsync();
            }

            // Generate a new session token for this login
            string sessionToken = Guid.NewGuid().ToString();
            user.SecurityStamp = sessionToken; // Use SecurityStamp for tracking session
            await _userManager.UpdateAsync(user);

            // Store session token in session storage
            HttpContext.Session.SetString("AuthToken", sessionToken);

            // Check if 2FA is enabled for the user
            if (await _userManager.GetTwoFactorEnabledAsync(user))
            {
                // Generate the 2FA token and send it via email
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                try
                {
                    Console.WriteLine($"[DEBUG] 2FA Code for {user.Email}: {token}");
                    _logger.LogInformation("2FA Code for {Email}: {Code}", user.Email, token);
                }
                catch (Exception ex)
                {
                    _logger.LogError("Failed to send 2FA email. Error: {ErrorMessage}", ex.Message);
                    ModelState.AddModelError("", "Unable to send 2FA email. Please try again later or contact support.");
                    return Page(); // Stay on login page with error message
                }

                HttpContext.Session.SetString("UserId", user.Id);
                return RedirectToPage("/Verify2FA");

            }

            // Proceed with normal login if 2FA is not enabled
            var result = await _signInManager.PasswordSignInAsync(user, LModel.Password, LModel.RememberMe, lockoutOnFailure: true);
            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in successfully: {Email}", user.Email);
                return RedirectToPage("/Index");
            }
            else if (result.IsLockedOut)
            {
                _logger.LogWarning("Account locked: {Email}", normalizedEmail);
                ModelState.AddModelError("", "Account locked due to multiple failed attempts. Try again later.");
                await LogAuditEvent(user.Email, "Account Locked Out");
                return Page();
            }
            else
            {
                _logger.LogWarning("Invalid login attempt for user: {Email}", normalizedEmail);
                ModelState.AddModelError("", "Invalid login attempt.");
                await LogAuditEvent(user.Email, "Login Failed");
                return Page();
            }
        }


        // Audit Logging Method
        private async Task LogAuditEvent(string userEmail, string action)
        {
            var logEntry = new AuditLog
            {
                UserEmail = userEmail,
                Action = action,
                Timestamp = DateTime.UtcNow,
                IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            };

            _context.AuditLogs.Add(logEntry);
            await _context.SaveChangesAsync();
        }

        private async Task SendEmail(string toEmail, string subject, string body)
        {
            if (string.IsNullOrWhiteSpace(toEmail))
            {
                _logger.LogError("Email sending failed: recipient email is null or empty.");
                return;
            }

            try
            {
                _logger.LogInformation("SMTP Settings: Server={Server}, Port={Port}, Username={Username}",
                    _configuration["EmailSettings:SmtpServer"],
                    _configuration["EmailSettings:Port"],
                    _configuration["EmailSettings:Username"]);

                // First attempt with port 587 (STARTTLS)
                await TrySendEmail(toEmail, subject, body, 587, enableSsl: false, useStartTls: true);
            }
            catch (Exception ex1)
            {
                _logger.LogWarning("Failed to send email using port 587. Retrying with port 465... Error: {ErrorMessage}", ex1.Message);

                try
                {
                    // Second attempt with port 465 (SSL)
                    await TrySendEmail(toEmail, subject, body, 465, enableSsl: true, useStartTls: false);
                }
                catch (Exception ex2)
                {
                    _logger.LogError("Email sending failed on both ports 587 and 465. Error: {ErrorMessage}", ex2.Message);
                    throw new Exception("Email sending failed. Please check your SMTP settings or use an alternative method.");
                }
            }
        }



        private async Task TrySendEmail(string toEmail, string subject, string body, int port, bool enableSsl, bool useStartTls)
        {
            using (var smtpClient = new SmtpClient(_configuration["EmailSettings:SmtpServer"], port))
            {
                smtpClient.Credentials = new NetworkCredential(
                    _configuration["EmailSettings:Username"],
                    _configuration["EmailSettings:Password"]);

                smtpClient.EnableSsl = enableSsl; // Required for port 465
                smtpClient.DeliveryMethod = SmtpDeliveryMethod.Network;
                smtpClient.UseDefaultCredentials = false;

                if (useStartTls)
                {
                    smtpClient.EnableSsl = false; // Must be false for STARTTLS to work
                    smtpClient.TargetName = "STARTTLS/smtp.gmail.com"; // Required for STARTTLS
                }

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(_configuration["EmailSettings:SenderEmail"]),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true
                };
                mailMessage.To.Add(toEmail);

                _logger.LogInformation("Attempting to send email via SMTP Server={Server}, Port={Port}, Using STARTTLS={StartTls}, Using SSL={SSL}",
                    _configuration["EmailSettings:SmtpServer"], port, useStartTls, enableSsl);

                await smtpClient.SendMailAsync(mailMessage);
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
