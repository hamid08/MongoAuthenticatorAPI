using MongoAuthenticatorAPI.Models.ViewModel;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace MongoAuthenticatorAPI.Services
{
    public interface ITokenService
    {
        TokenResultVM TokenGenerator(Guid userId, string username);
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
        string GenerateRefreshToken();
        (string token, DateTime expiration) GenerateAccessToken(IEnumerable<Claim> claims);
    }
}
