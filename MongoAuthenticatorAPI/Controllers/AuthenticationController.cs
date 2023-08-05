using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MongoAuthenticatorAPI.Dtos;
using MongoAuthenticatorAPI.Models;
using MongoAuthenticatorAPI.Models.ViewModel;
using MongoAuthenticatorAPI.Services;

namespace MongoAuthenticatorAPI.Controllers
{
    [ApiController]
    [Route("api/v1/authenticate")]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly ITokenService _tokenService;
        public AuthenticationController(ITokenService tokenService,UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _tokenService = tokenService;
        }
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            //بررسی درست بودن یوزر و پسورد
            var user = await _userManager.FindByEmailAsync(request.Email);
            var validPassword = await _userManager.CheckPasswordAsync(user, request.Password);

            if (user is null || !validPassword) return BadRequest("Invalid email/password");

            //ایجاد توکن
            var result = _tokenService.TokenGenerator(user.Id, user.UserName);

            //ذخیره رفرش توکن
           
            user.ExpirationRefreshToken = result.RefreshTokenExpiration;
            user.RefreshToken = result.RefreshToken;
            await _userManager.UpdateAsync(user);

            return Ok(result);
        }

        [HttpPost]
        public async Task<IActionResult> Refresh(string token, string refreshToken)
        {
            //گرفتن اطلاعات درون توکن
            var principal = _tokenService.GetPrincipalFromExpiredToken(token);

            //نام کاربری
            var username = principal.Identity.Name; //this is mapped to the Name claim by default

            //پیدا کردن کاربر و برابر نبودن رفرش توکن ورودی و رفرش توکن در دیتابیس
            var user = await _userManager.FindByNameAsync(username);
            if (user == null || user.RefreshToken != refreshToken) return BadRequest();

            //چک کردن ولید بودن رفرش توکن ثبت شده
            if (user.ExpirationRefreshToken < DateTime.Now)
            return BadRequest();

            //تولید توکن جدید
            var newJwtToken = _tokenService.GenerateAccessToken(principal.Claims);

            //تولید رفرش توکن جدید
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            //ذخیره رفرش توکن جدید
            user.RefreshToken = newRefreshToken;
            user.ExpirationRefreshToken = DateTime.Now.AddDays(5);
            await _userManager.UpdateAsync(user);


            return Ok(new TokenResultVM
            {
                AccessToken = newJwtToken.token,
                AccessTokenExpiration = newJwtToken.expiration,
                RefreshTokenExpiration = DateTime.UtcNow,
                RefreshToken = newRefreshToken
            });

            //return new ObjectResult(new
            //{
            //    token = newJwtToken.token,
            //    expiration = newJwtToken.expiration,
            //    currentTime = DateTime.UtcNow,
            //    refreshToken = newRefreshToken
            //});


        }


        [HttpPost]
        [Route("roles/add")]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request)
        {
            var appRole = new ApplicationRole { Name = request.Role };
            var createRole = await _roleManager.CreateAsync(appRole);

            return Ok(new { message = "role created succesfully" });
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var result = await RegisterAsync(request);

            return result.Success ? Ok(result) : BadRequest(result.Message);

        }

        private async Task<RegisterResponse> RegisterAsync(RegisterRequest request)
        {
            try
            {
              
                var userExists = await _userManager.FindByEmailAsync(request.Email);
                if(userExists != null) return new RegisterResponse { Message = "User already exists", Success = false };

                //if we get here, no user with this email..

                userExists = new ApplicationUser
                {
                    FirstName = request.FullName,
                    Email = request.Email,
                    ConcurrencyStamp = Guid.NewGuid().ToString(),
                    UserName = request.Email,

                };
                var createUserResult = await _userManager.CreateAsync(userExists, request.Password);
                if(!createUserResult.Succeeded) return new RegisterResponse { Message = $"Create user failed {createUserResult?.Errors?.First()?.Description}", Success = false };
                //user is created...
                //then add user to a role...
                var addUserToRoleResult = await _userManager.AddToRoleAsync(userExists, "USER");
                if(!addUserToRoleResult.Succeeded) return new RegisterResponse { Message = $"Create user succeeded but could not add user to role {addUserToRoleResult?.Errors?.First()?.Description}", Success = false };

                //all is still well..
                return new RegisterResponse
                {
                    Success = true,
                    Message = "User registered successfully"
                };



            }
            catch (Exception ex)
            {
                return new RegisterResponse { Message = ex.Message, Success = false };
            }
        }

        //[HttpPost]
        //[Route("login")]
        //[ProducesResponseType((int) HttpStatusCode.OK , Type = typeof(LoginResponse))]
        //public async Task<IActionResult> Login([FromBody] LoginRequest request)
        //{
        //    var result = await LoginAsync(request);

        //    return result.Success ? Ok(result) : BadRequest(result.Message);


        //}

        private async Task<LoginResponse> LoginAsync(LoginRequest request)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(request.Email);
                var validPassword = await _userManager.CheckPasswordAsync(user, request.Password);

                if (user is null || !validPassword) return new LoginResponse { Message = "Invalid email/password", Success = false };

               var accessFaild = await _userManager.AccessFailedAsync(user);

                //all is well if ew reach here
                var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
            };
                var roles = await _userManager.GetRolesAsync(user);
                var roleClaims = roles.Select(x => new Claim(ClaimTypes.Role, x));
                claims.AddRange(roleClaims);

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("1swek3u4uo2u4a6e"));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var expires = DateTime.Now.AddMinutes(30);

                var token = new JwtSecurityToken(
                    issuer: "https://localhost:5001",
                    audience: "https://localhost:5001",
                    claims: claims,
                    expires: expires,
                    signingCredentials: creds

                    );

                return new LoginResponse
                {
                    AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
                    Message = "Login Successful",
                    Email = user?.Email,
                    Success = true,
                    UserId = user?.Id.ToString()
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return new LoginResponse { Success = false, Message = ex.Message };
            }


        }
    }
}

