using DotNetCoreAPITokenAuth.Authontications;
using DotNetCoreAPITokenAuth.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace DotNetCoreAPITokenAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthonticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration _configuration;

        public AuthonticationController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var userExist = await userManager.FindByNameAsync(model.UserName);

            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { 
                Status = "Error",
                Massage = "The Username is already exists!"
                });
            }

            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.UserName
            };

            var result = await userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response
                {
                    Status = "Error",
                    Massage = "User creation error occured!"
                });
            }

            return Ok(new Response { Status="Success",Massage="User Created Successfully!" });
        }



        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await userManager.FindByNameAsync(model.UserName);
            if(user!=null&& await userManager.CheckPasswordAsync(user,model.Password))
            {
                var userRoles = await userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name,user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
                };

                foreach(var userrole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userrole));
                }

                var authSigninKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
                

                /*
                 * JwtSecurityToken(
                 * string issuer = null, 
                 * string audience = null, 
                 * IEnumerable<Claim> claims = null, 
                 * DateTime? notBefore = null, 
                 * DateTime? expires = null, 
                 * SigningCredentials signingCredentials = null
                 * );
                 */
                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    claims:authClaims,
                    notBefore:null,
                    expires:DateTime.Now.AddHours(1),
                    signingCredentials: new SigningCredentials(authSigninKey, SecurityAlgorithms.HmacSha256)
                    );
               
                return Ok(new{token = new JwtSecurityTokenHandler().WriteToken(token)}); 
            }

            return Unauthorized();
        }



        [HttpPost]
        [Route("RegisterAdmin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            var userExist = await userManager.FindByNameAsync(model.UserName);

            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response
                {
                    Status = "Error",
                    Massage = "The Username is already exists!"
                });
            }

            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.UserName
            };

            var result = await userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response
                {
                    Status = "Error",
                    Massage = "User creation error occured!"
                });
            }

            if(!await roleManager.RoleExistsAsync(UserRole.Admin))
            {
                await roleManager.CreateAsync(new IdentityRole(UserRole.Admin));
            }

            if (!await roleManager.RoleExistsAsync(UserRole.User))
            {
                await roleManager.CreateAsync(new IdentityRole(UserRole.User));
            }

            if (await roleManager.RoleExistsAsync(UserRole.Admin))
            {
                await userManager.AddToRoleAsync(user,UserRole.Admin);
            }


            return Ok(new Response { Status = "Success", Massage = "User Created Successfully!" });
        }


    }
}
