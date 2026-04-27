namespace MasterPassword.BusinessLogic.LoadSecondaryAccount
{
    public sealed class LoadSecondaryAccountResponse : AppResponse
    {
        public LoadSecondaryAccountResponse(bool success) 
            : base(success)
        {
        }

        public string Username { get; internal set; }

        public string AccountName { get; internal set; }

        public string Password { get; internal set; }

        public string Url { get; internal set; }
    }
}
