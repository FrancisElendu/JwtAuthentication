using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuthentication
{
    //need to package this to nuget.org
    public interface IJwtTokenService
    {
        string GenerateToken(string? userId = null, string? role = null, int? expirationMinutes = null);
    }
}
