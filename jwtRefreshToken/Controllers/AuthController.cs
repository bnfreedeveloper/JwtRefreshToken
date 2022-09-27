using jwtRefreshToken.Dtos;
using jwtRefreshToken.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace jwtRefreshToken.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        public static User user = new User();
        private readonly IConfiguration _config;

        public AuthController(IConfiguration config)
        {
            _config = config;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {

            PasswordHash(request.Password, out byte[] passwordhash, out byte[] salt);
            user.Username = request.Username;
            user.Password = passwordhash;
            user.PassworSalt = salt;
            //simulate storing user to database
            await Task.FromResult(user);
            return Ok(user);
        }
        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {

            //simulating getting the user grom database
            await Task.FromResult(request);

            if (user.Username != request.Username)
            {

                return BadRequest("user not found");
            }
            if (!verifyHash(request.Password, user.Password, user.PassworSalt))
            {
                return BadRequest("wrong credentials");
            }
            var token = GenerateToken(user);
            var refreshToken = GenerateRefreshToken();
            await SendRefreshToken(refreshToken);
            return Ok(token);

        }
        [HttpPost("refresh")]

        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshT = Request.Cookies["refreshToken"];

            //simulate calling database to check refreshtoken associated with the user
            var userFromDatabase = await Task.FromResult(user);
            var userRefreshToken = userFromDatabase.RefreshT;
            if (!userRefreshToken.Token.Equals(refreshT))
            {
                return Unauthorized("The refresh token is invalid");
            }

            else if (userRefreshToken.ExpiresAt < DateTime.Now)
            {
                return Unauthorized("Token expired");
            }
            else
            {
                var newToken = GenerateToken(userFromDatabase);
                var newRefreshToken = GenerateRefreshToken();
                await SendRefreshToken(newRefreshToken);
                return Ok(newToken);
            }
        }

        [HttpGet("test")]
        [Authorize(Roles = "administrator")]
        public async Task<ActionResult<string>> test()
        {
            return Ok(await Task.FromResult("test réussi"));
        }

        private string GenerateToken(User user)
        {
            var claims = new List<Claim>
            {
             new Claim(ClaimTypes.NameIdentifier, user.Username),
             new Claim(ClaimTypes.Name,user.Username),
             new Claim(ClaimTypes.Role , "administrator")
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("JwtKey").Value));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(10),
                    signingCredentials: credentials
                );
            return new JwtSecurityTokenHandler().WriteToken(token);

        }

        //METHOD FOR HASHING PASSWORD
        private void PasswordHash(string password, out byte[] passworHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passworHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }
        private bool verifyHash(string password, byte[] passwordHash, byte[] salt)
        {
            using (var hmac = new HMACSHA512(salt))
            {
                var hashedPassword = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return hashedPassword.SequenceEqual(passwordHash);
            }
        }

        private RefreshToken GenerateRefreshToken()
        {
            var refreshT = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                ExpiresAt = DateTime.Now.AddDays(4),
                CreatedAt = DateTime.Now,

            };
            return refreshT;

        }
        private async Task SendRefreshToken(RefreshToken refresT)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = refresT.ExpiresAt
            };
            Response.Cookies.Append("refreshToken", refresT.Token, cookieOptions);

            //simulate call to database for updating the user with the refresh token
            await Task.FromResult(user.RefreshT = refresT);


        }


    }
}
