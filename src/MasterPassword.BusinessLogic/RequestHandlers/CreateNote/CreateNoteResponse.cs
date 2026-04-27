namespace MasterPassword.BusinessLogic.CreateNote
{
    public sealed class CreateNoteResponse : AppResponse
    {
        public CreateNoteResponse(bool success) 
            : base(success)
        {
        }

        public string NoteId { get; internal set; }
    }
}
