using System;

namespace MasterPassword.BusinessLogic.RequestHandlers.RefreshSession
{
    public sealed class RefreshSessionResponse : AppResponse
    {
        public RefreshSessionResponse(bool success)
            : base(success)
        {
        }

        public string Token { get; internal set; }

        public DateTimeOffset TokenExpiration { get; internal set; }
    }
}
