using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace GenerateTestJwt
{
    // This program generates a simple JWT string for use in tests. It makes no claims,
    // it is not valid on any real system, and it lives for 15 years so it will be a
    // while before your tests start failing because the token expired.
    //
    // NOTE: I'd've loved to generate a token that lasts for 1000 years so your tests
    // never fail, but the Microsoft authentication architecture suffers from the
    // Year 2038 problem. See https://github.com/IdentityModel/IdentityModel/issues/137
    // and https://en.wikipedia.org/wiki/Year_2038_problem.
    internal static class Program
    {
        private const int YEARS_TO_LIVE = 15;

        private static int Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.Error.WriteLine("usage: GenerateTestJwt <issuer> <key>");
                return 1;
            }

            string issuer = args[0];
            string key = args[1];

            Console.WriteLine($"Creating token for issuer \"{issuer}\" with key \"{key}\"\n");

            string jwtString = CreateToken(issuer, key);
            Console.WriteLine(jwtString + "\n");

            bool tokenIsValid = ValidateToken(jwtString, issuer, key);

            return tokenIsValid ? 0 : 1;
        }

        private static string CreateToken(string issuer, string key)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(Array.Empty<Claim>()),
                Expires = DateTime.UtcNow.AddYears(YEARS_TO_LIVE),
                Issuer = issuer,
                SigningCredentials = credentials
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken jwt = tokenHandler.CreateToken(tokenDescriptor);
            string jwtString = tokenHandler.WriteToken(jwt);

            return jwtString;
        }

        private static bool ValidateToken(string jwtString, string issuer, string key)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var expectedIssuer = issuer;
                var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(key));
                TokenValidationParameters validationParams = new()
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = false,
                    ValidIssuer = expectedIssuer,
                    ValidateLifetime = true,
                    IssuerSigningKey = securityKey,
                };

                handler.ValidateToken(jwtString, validationParams, out SecurityToken validatedToken);

                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return false;
            }
        }
    }
}
