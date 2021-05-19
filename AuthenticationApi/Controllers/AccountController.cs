using AuthenticationApi.Dtos;
using AuthenticationApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private UserManager<ApplicationUser> _applicationUserManager;
        private JWT _jwtOptions;

        public AccountController(
            UserManager<ApplicationUser> applicationUserManager,
            IOptions<JWT> jwtOptions
            )
        {
            _applicationUserManager = applicationUserManager;
            _jwtOptions = jwtOptions.Value;
        }

    


        [AllowAnonymous]
        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            try
            {
                var userToVerify = await _applicationUserManager.FindByNameAsync(model.Username);
                if (userToVerify == null)
                {
                   
                    return BadRequest("Invalid username/password");
                }

                if (!await _applicationUserManager.CheckPasswordAsync(userToVerify, model.Password))
                {
                    return BadRequest("Invalid username/password");
                }

                JwtSecurityToken token = await CreateJwtToken(userToVerify);
                var jwtSecurityToken = new JwtSecurityTokenHandler().WriteToken(token);
                var value = new
                {
                    Message = "Login Successfully",
                    IsSuccess = true,
                    Token= jwtSecurityToken
                };


                return base.Ok(value);
             

            }
            catch (Exception e)
            {
                throw;
            }

        }


        [AllowAnonymous]
        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {

            try
            {
                if (!ModelState.IsValid)
                {

                    return BadRequest(ModelState);
                }
                var userIdentity = new ApplicationUser
                {
                    Email = model.Email,
                    UserName = model.UserName,                
                    PhoneNumber = model.PhoneNumber,                  
                };               

                var result = await _applicationUserManager.CreateAsync(userIdentity, model.Password);


                if (!result.Succeeded)
                {
                    return BadRequest(result.Errors);
                }

                return Ok(new { 
                
                    Message="",
                    IsSuccess=true,
                });
            }
            catch (Exception ex)
            {

                return BadRequest(ex.Message);
            }

        }




        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {


            var userClaims = await _applicationUserManager.GetClaimsAsync(user);
            var roles = await _applicationUserManager.GetRolesAsync(user);

            var roleClaims = new List<Claim>();            

            var claims = new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(ClaimTypes.NameIdentifier, user.UserName),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Sid, user.Id),
                    new Claim(ClaimTypes.MobilePhone, user.PhoneNumber),
                }
                .Union(userClaims)
                .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwtOptions.Issuer,
                audience: _jwtOptions.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtOptions.DurationInMinutes),
                signingCredentials: signingCredentials);
            return jwtSecurityToken;
        }



    }
}
