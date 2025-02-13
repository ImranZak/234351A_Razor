using System;
using System.ComponentModel.DataAnnotations;

namespace _234351A_Razor.Models
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string UserEmail { get; set; } // User involved in the action

        [Required]
        public string Action { get; set; } // "Login Success", "Login Failed", "Logout", "Session Expired"

        [Required]
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        public string IPAddress { get; set; } // Capture IP Address
    }
}
