namespace MasterPassword.BusinessLogic.UpdateNote
{
    public sealed class UpdateNoteRequest
    {
        public string? PrimaryAccountId { get; set; }

        public string? UserKey { get; set; }

        public string SecondaryAccountId { get; set; } = string.Empty;

        public string NoteId { get; set; } = string.Empty;

        public string Title { get; set; } = string.Empty;

        public string Description { get; set; } = string.Empty;
    }
}
