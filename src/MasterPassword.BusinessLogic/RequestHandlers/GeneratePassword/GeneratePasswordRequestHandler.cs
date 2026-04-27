using System;
using System.Collections.Generic;
using System.Linq;

namespace MasterPassword.BusinessLogic.GeneratePassword
{
    public interface IGeneratePasswordRequestHandler
    {
        GeneratePasswordResponse Handle(GeneratePasswordRequest request);
    }

    internal sealed class GeneratePasswordRequestHandler : IGeneratePasswordRequestHandler
    {
        public GeneratePasswordResponse Handle(GeneratePasswordRequest request)
        {
            Random random = new Random();

            if (request.Length == 0)
                request.Length = 10;

            var specialCharacters = new List<string> { "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "+", "=", "<", ">", "?"};

            if(!string.IsNullOrEmpty(request.Exclusion))
            {
                var exclusionList = request.Exclusion.Split().ToList();
                foreach (var e in exclusionList)
                {
                    specialCharacters.Remove(e);
                }
            }

            string password = string.Empty;
            while(password.Length < request.Length)
            {
                int r = random.Next(0, 4);

                if (r == 0)//lowercase
                {
                    int v = random.Next(97, 123);
                    char c = (char)v;
                    password += c.ToString();
                }
                if (r == 1 && request.IncludeCapital)//uppercase
                {
                    int v = random.Next(65, 91);
                    char c = (char)v;
                    password += c.ToString();
                }
                if (r == 2 && request.IncludeNumbers)//numbers
                {
                    int v = random.Next(48, 58);
                    char c = (char)v;
                    password += c.ToString();
                }
                if (r == 3 && request.IncludeSpecial)//special characters
                {
                    int v = random.Next(0, specialCharacters.Count);
                    password += specialCharacters[v];
                }
            }

            return new GeneratePasswordResponse(true) { Password = password };
        }
    }
}
