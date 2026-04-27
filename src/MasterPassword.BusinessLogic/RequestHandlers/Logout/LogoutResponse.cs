namespace MasterPassword.BusinessLogic.RequestHandlers.Logout
{
    public sealed class LogoutResponse : AppResponse
    {
        public LogoutResponse(bool success)
            : base(success)
        {
        }
    }
}
