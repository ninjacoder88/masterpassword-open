namespace MasterPassword.BusinessLogic.CreatePrimaryAccount
{
    public sealed class CreatePrimaryAccountResponse : AppResponse
    {
        public CreatePrimaryAccountResponse(bool success)
            : base(success)
        {
        }

        public string Id { get; internal set; }
    }
}
