using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.Collections.Generic;
using System.Text.Json;

namespace _234351A_Razor.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [DataType(DataType.Text)]
        public string FirstName { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string LastName { get; set; }

        [Required]
        [DataType(DataType.CreditCard)]
        public string CreditCard { get; set; } // Will be encrypted

        [Required]
        [DataType(DataType.PhoneNumber)]
        public string MobileNo { get; set; }

        [Required]
        [DataType(DataType.MultilineText)]
        public string BillingAddress { get; set; }

        [Required]
        [DataType(DataType.MultilineText)]
        public string ShippingAddress { get; set; } // Allow all special characters

        [Required]
        [DataType(DataType.Upload)]
        public string PhotoPath { get; set; } // JPG file path

        public string? SessionToken { get; set; }

        // NEW: Store previous passwords (limit to last 2)
        public ICollection<PasswordHistory> PreviousPasswords { get; set; } = new List<PasswordHistory>();
        public DateTime? PasswordChangedAt { get; set; } // ✅ New Property to Track Password Changes


    }
}
