namespace MasterPassword.BusinessLogic.CreateNote
{
    public sealed class CreateNoteRequest
    {
        public string? PrimaryAccountId { get; set; }

        public string? UserKey { get; set; }

        public string SecondaryAccountId { get; set; } = string.Empty;

        public string Title { get; set; } = string.Empty;

        public string Description { get; set; } = string.Empty;
    }
}
