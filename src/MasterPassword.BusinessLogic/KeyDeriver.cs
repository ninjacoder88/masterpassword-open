using System;
using System.Text;

namespace MasterPassword.BusinessLogic.RequestHandlers
{
    public interface IKeyDeriver
    {
        string DeriveKeyFromPassword(string password);
    }

    internal sealed class KeyDeriver : IKeyDeriver
    {
        public string DeriveKeyFromPassword(string password)
        {
            string encodedPassword = Convert.ToBase64String(Encoding.UTF8.GetBytes(password));
            return encodedPassword.Length > 32 ? encodedPassword.Substring(0, 32) : encodedPassword.PadLeft(32);
        }
    }
}
