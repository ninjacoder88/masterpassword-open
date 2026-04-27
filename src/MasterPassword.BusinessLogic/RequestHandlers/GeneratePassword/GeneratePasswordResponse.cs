namespace MasterPassword.BusinessLogic.GeneratePassword
{
    public sealed class GeneratePasswordResponse : AppResponse
    {
        public GeneratePasswordResponse(bool success) 
            : base(success)
        {
        }

        public string Password { get; internal set; }
    }
}
