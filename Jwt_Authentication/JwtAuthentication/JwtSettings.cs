﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuthentication
{
    public class JwtSettings
    {
        public string? UserId { get; set; }
        public string? Role { get; set; }
        public int ExpirationMinutes { get; set; }
        public string? SecretKey { get; set; }
        public string? Issuer { get; set; }
        public string? Audience { get; set; }
    }
}
