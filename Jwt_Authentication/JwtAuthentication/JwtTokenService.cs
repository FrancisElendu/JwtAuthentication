using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthentication
{
    public class JwtTokenService : IJwtTokenService
    {
        private readonly JwtSettings _jwtSettings;

        public JwtTokenService(JwtSettings jwtSettings)
        {
            _jwtSettings = jwtSettings;
        }

        public string GenerateToken(string? userId = null, string? role = null, int? expirationMinutes = null)
        {
            // Fallback to settings values if not provided
            userId ??= _jwtSettings.UserId ?? throw new ArgumentNullException(nameof(userId), "User ID cannot be null");
            role ??= _jwtSettings.Role ?? throw new ArgumentNullException(nameof(role), "Role cannot be null");
            var expiration = expirationMinutes ?? _jwtSettings.ExpirationMinutes;

            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub, userId),
            new Claim(ClaimTypes.Role, role),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

            var secretKey = _jwtSettings.SecretKey ?? throw new ArgumentNullException(nameof(_jwtSettings.SecretKey), "Secret key cannot be null");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(expiration),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
