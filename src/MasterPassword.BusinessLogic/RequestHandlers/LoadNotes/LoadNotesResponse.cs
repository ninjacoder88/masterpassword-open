namespace MasterPassword.BusinessLogic.LoadNotes
{
    public sealed class LoadNotesResponse : AppResponse
    {
        public LoadNotesResponse(bool success) 
            : base(success)
        {
        }

        public object Notes { get; internal set; }
    }
}
