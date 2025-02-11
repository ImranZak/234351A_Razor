using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

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
    }
}
