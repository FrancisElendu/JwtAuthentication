using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace JwtAuthentication
{
    public static class JwtAuthenticationExtensions
    {
        public static void AddJwtAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            // Bind JwtSettings from configuration
            var jwtSettings = new JwtSettings();
            configuration.Bind("JwtSettings", jwtSettings);

            var secretKey = jwtSettings.SecretKey ?? throw new ArgumentNullException(nameof(jwtSettings.SecretKey), "Secret key cannot be null");
            var key = Encoding.UTF8.GetBytes(secretKey);
            //var key = Encoding.UTF8.GetBytes(jwtSettings.SecretKey);

            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings.Issuer,
                    ValidAudience = jwtSettings.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                };
            });

            // Register JwtSettings and JwtTokenService
            services.AddSingleton(jwtSettings);
            services.AddSingleton<IJwtTokenService, JwtTokenService>();
        }
    }
}
