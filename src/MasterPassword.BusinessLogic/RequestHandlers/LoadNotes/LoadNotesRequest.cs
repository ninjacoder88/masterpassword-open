namespace MasterPassword.BusinessLogic.LoadNotes
{
    public sealed class LoadNotesRequest
    {
        public string PrimaryAccountId { get; set; }

        public string SecondaryAccountId { get; set; }

        public string UserKey { get; set; }
    }
}
