using System;
using System.Collections.Generic;
using System.Linq;

namespace MasterPassword.BusinessLogic
{
    public interface ITokenGenerator
    {
        string GenerateToken();
    }

    internal sealed class TokenGenerator : ITokenGenerator
    {
        public string GenerateToken()
        {
            List<int> asciiIds = new List<int>();
            asciiIds.AddRange(Enumerable.Range(48, 10));
            asciiIds.AddRange(Enumerable.Range(65, 26));
            asciiIds.AddRange(Enumerable.Range(97, 26));

            Random random = new Random();
            string str = "";
            for (int i = 0; i < 64; i++)
            {
                int asciiId = asciiIds[random.Next(0, asciiIds.Count)];
                str += (char)asciiId;
            }
            return str;
        }
    }
}
