namespace MasterPassword.Models
{
    public class DefaultResponse
    {
        public DefaultResponse(bool success)
        {
            Success = success;
        }

        public bool Success { get; }

        public string Message { get; set; }

        public object Obj { get; set; }
    }
}
