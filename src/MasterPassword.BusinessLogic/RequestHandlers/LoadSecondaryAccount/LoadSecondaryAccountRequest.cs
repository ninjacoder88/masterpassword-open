namespace MasterPassword.BusinessLogic.LoadSecondaryAccount
{
    public sealed class LoadSecondaryAccountRequest
    {
        public string Id { get; set; }

        public string PrimaryAccountId { get; set; }

        public string UserKey { get; set; }
    }
}
