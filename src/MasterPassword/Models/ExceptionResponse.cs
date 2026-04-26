namespace MasterPassword.Models
{
    public class ExceptionResponse
    {
        public ExceptionResponse(string errorMessage)
        {
            ErrorMessage = errorMessage;
        }

        public bool Success => false;

        public string ErrorMessage { get; set; }
    }
}
