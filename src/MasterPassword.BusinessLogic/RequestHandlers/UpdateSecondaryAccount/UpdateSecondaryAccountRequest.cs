namespace MasterPassword.BusinessLogic.UpdateSecondaryAccount
{
    public sealed class UpdateSecondaryAccountRequest
    {
        public string? PrimaryAccountId { get; set; }

        public string? UserKey { get; set; }

        public string SecondaryAccountId { get; set; } = string.Empty;

        public string FieldName { get; set; } = string.Empty;

        public string Value { get; set; } = string.Empty;
    }
}
