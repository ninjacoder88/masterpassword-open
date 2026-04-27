using System;

namespace MasterPassword.BusinessLogic.Login
{
    public sealed class LoginResponse : AppResponse
    {
        public LoginResponse(bool success) 
            : base(success)
        {

        }

        public string Id { get; internal set; }

        public string UserKey { get; set; }

        public string Token { get; internal set; }

        public DateTimeOffset TokenExpiration { get; internal set; }
    }
}
