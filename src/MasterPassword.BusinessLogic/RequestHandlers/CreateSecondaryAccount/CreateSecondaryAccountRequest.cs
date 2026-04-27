namespace MasterPassword.BusinessLogic.CreateSecondaryAccount
{
    public sealed class CreateSecondaryAccountRequest
    {
        public string AccountName { get; set; } = string.Empty;

        public string Url { get; set; } = string.Empty;

        public string Username { get; set; } = string.Empty;

        public string Password { get; set; } = string.Empty;

        public string? PrimaryAccountId { get; set; }

        public string? UserKey { get; set; }
    }
}
