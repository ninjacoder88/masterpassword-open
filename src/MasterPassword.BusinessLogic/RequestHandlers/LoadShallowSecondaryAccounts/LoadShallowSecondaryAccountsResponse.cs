using System.Collections.Generic;

namespace MasterPassword.BusinessLogic.LoadSecondaryAccounts
{
    public sealed class LoadShallowSecondaryAccountsResponse : AppResponse
    {
        public LoadShallowSecondaryAccountsResponse(bool success) 
            : base(success)
        {
        }

        public List<ShallowSecondaryAccount> Accounts { get; internal set; }
    }

    public class ShallowSecondaryAccount
    {
        public string Id { get; set; }

        public string AccountName { get; set; }

        public string Favicon { get; set; }

        public string Category { get; set; }
    }
}
