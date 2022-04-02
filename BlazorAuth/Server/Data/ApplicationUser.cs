using Microsoft.AspNetCore.Identity;

namespace BlazorAuth.Server.Data
{
    public class ApplicationUser : IdentityUser
    {
        public string JwtToken { get; set; }
    }
}
