namespace MasterPassword.BusinessLogic.CreateSecondaryAccount
{
    public sealed class CreateSecondaryAccountResponse : AppResponse
    {
        public CreateSecondaryAccountResponse(bool success) 
            : base(success)
        {
        }

        public string Id { get; internal set; }
    }
}
