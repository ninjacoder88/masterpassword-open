namespace MasterPassword.BusinessLogic.RequestHandlers.RefreshSession
{
    public sealed class RefreshSessionRequest
    {
        public string UserId { get; set; }

        public string UserKey { get; set; }
    }
}
