namespace MasterPassword.BusinessLogic.DeleteSecondaryAccount
{
    public sealed class DeleteSecondaryAccountRequest
    {
        public string? UserKey { get; set; }

        public string SecondaryAccountId { get; set; } = string.Empty;

        public string? PrimaryAccountId { get; set; }
    }
}
