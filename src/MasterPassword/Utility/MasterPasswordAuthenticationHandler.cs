using MasterPassword.BusinessLogic;
using MasterPassword.DataAccess.MongoDbAtlas;
using MasterPassword.Extension;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace MasterPassword
{
    public class MasterPasswordAuthenticationHandler : AuthenticationHandler<MasterPasswordAuthOptions>
    {
        public MasterPasswordAuthenticationHandler(IOptionsMonitor<MasterPasswordAuthOptions> options, ILoggerFactory logger, 
            UrlEncoder encoder, ISystemClock clock, IMongoDbRepository repository, IEncryptor encryptor) 
            : base(options, logger, encoder, clock)
        {
            _repository = repository;
            _encryptor = encryptor;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
                return AuthenticateResult.NoResult();

            var authHeader = Request.Headers.Authorization;
            if(!AuthenticationHeaderValue.TryParse(authHeader, out var authenticationHeaderValue))
                return AuthenticateResult.NoResult();

            if(authenticationHeaderValue.Scheme != "Bearer")
                return AuthenticateResult.NoResult();

            var token = authenticationHeaderValue.Parameter;
            if (string.IsNullOrEmpty(token))
                return AuthenticateResult.NoResult();

            var userId = Request.HttpContext.GetUserId();
            if (string.IsNullOrEmpty(userId))
                return AuthenticateResult.Fail("No session is active");

            var primaryAccount = await _repository.LoadPrimaryAccountByIdAsync(userId);
            if (primaryAccount == null)
                return AuthenticateResult.Fail("Invalid user");

            var userKey = Request.HttpContext.GetUserKey();

            byte[] encryptionKeyBytes = Encoding.UTF8.GetBytes(userKey);
            DateTimeOffset now = DateTimeOffset.UtcNow;

            if (primaryAccount.Token == null)
                return AuthenticateResult.Fail("Token not set");

            if (primaryAccount.TokenExpiration == null)
                return AuthenticateResult.Fail("Token expiration not set");

            var decryptedToken = _encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, primaryAccount.Token);
            var decryptedExpiration = _encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, primaryAccount.TokenExpiration);

            if (decryptedToken != token)
                return AuthenticateResult.Fail("Invalid token");

            if (!DateTimeOffset.TryParse(decryptedExpiration, out DateTimeOffset expiration))
                return AuthenticateResult.Fail("Invalid token expiration");

            if (expiration < now)
                return AuthenticateResult.Fail("Token has expired");

            var claims = new List<Claim> { new Claim(ClaimTypes.Name, token) };
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new GenericPrincipal(identity, null);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }

        private readonly IMongoDbRepository _repository;
        private readonly IEncryptor _encryptor;
    }

    public class MasterPasswordAuthOptions : AuthenticationSchemeOptions
    {
        
    }
}
