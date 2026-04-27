namespace MasterPassword.BusinessLogic
{
    public abstract class AppResponse
    {
        public AppResponse(bool success)
        {
            Success = success;
        }

        public bool Success { get; }

        public string ErrorMessage { get; set; }
    }
}
