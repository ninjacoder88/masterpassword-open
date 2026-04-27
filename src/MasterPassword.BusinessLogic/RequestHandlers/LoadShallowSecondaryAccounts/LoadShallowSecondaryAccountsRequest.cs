namespace MasterPassword.BusinessLogic.LoadSecondaryAccounts
{
    public sealed class LoadShallowSecondaryAccountsRequest
    {
        public string PrimaryAccountId { get; set; }

        public string UserKey { get; set; }
    }
}
