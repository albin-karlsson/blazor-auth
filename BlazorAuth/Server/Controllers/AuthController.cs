using BlazorAuth.Server.Data;
using BlazorAuth.Shared;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace BlazorAuth.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AuthController(IConfiguration configuration, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager)
        {
            _configuration = configuration;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }

        [HttpPost]
        public async Task<ActionResult<string>> LoginUser(UserDto request)
        {
            // No need to log the user in to the Identity Db, everything is handled by the token

            ApplicationUser user = await _signInManager.UserManager.FindByNameAsync(request.Username);

            user.JwtToken = await CreateToken(request);

            var updateResult = await _signInManager.UserManager.UpdateAsync(user);

            if (updateResult.Succeeded)
            {
                return Ok(user.JwtToken);
            }
            else
            {
                return BadRequest();
            }
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> RegisterUser(UserDto request)
        {
            ApplicationUser newUser = new()
            {
                UserName = request.Username,
                JwtToken = await CreateToken(request)
            };

            var createUserResult = await _signInManager.UserManager.CreateAsync(newUser, request.Password);

            if (createUserResult.Succeeded)
            {
                return Ok("User created");
            }
            else
            {
                return BadRequest("User could not be registered");
            }
        }

        [HttpPost]
        [Route("admin")]
        public async Task<ActionResult<string>> MakeAdmin(TokenDto token)
        {
            // Get all users
            // Check what user has the token
            // Make that user admin

            var users = await _signInManager.UserManager.Users.ToListAsync();
            var currentUser = users.FirstOrDefault(u => u.JwtToken == token.Token);

            if (currentUser != null)
            {
                if (!await _roleManager.RoleExistsAsync("Admin"))
                {
                    await CreateAdminRole();
                }

                var addToRoleResult = await _signInManager.UserManager.AddToRoleAsync(currentUser, "Admin");

                if (addToRoleResult.Succeeded)
                {
                    // Create new jwt token with role included
                    string newToken = await CreateToken(new UserDto()
                    {
                        Username = currentUser.UserName
                    });

                    // Add the new token to the database
                    currentUser.JwtToken = newToken;
                    await _signInManager.UserManager.UpdateAsync(currentUser);

                    return Ok(newToken);
                }
            }

            return BadRequest();
        }

        private async Task<string> CreateToken(UserDto user)
        {
            List<Claim> claims = new()
            {
                new Claim(ClaimTypes.Name, user.Username)
            };

            var userRoles = await CheckRoles(user);

            foreach (var userRole in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("Secrets:Token").Value));

            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private async Task<List<string>> CheckRoles(UserDto user)
        {
            var identityUser = await _signInManager.UserManager.FindByNameAsync(user.Username);

            if (identityUser != null)
            {
                var roles = await _signInManager.UserManager
                .GetRolesAsync(identityUser);

                return roles.ToList();
            }

            return new List<string>();
        }

        private async Task CreateAdminRole()
        {
            IdentityRole adminRole = new()
            {
                Name = "Admin"
            };

            await _roleManager.CreateAsync(adminRole);
        }
    }
}
