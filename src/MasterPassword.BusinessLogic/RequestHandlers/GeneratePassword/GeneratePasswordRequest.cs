namespace MasterPassword.BusinessLogic.GeneratePassword
{
    public sealed class GeneratePasswordRequest
    {
        public int Length { get; set; }

        public bool IncludeCapital { get; set; }

        public bool IncludeNumbers { get; set; }

        public bool IncludeSpecial { get; set; }

        public string? Exclusion { get; set; }
    }
}
