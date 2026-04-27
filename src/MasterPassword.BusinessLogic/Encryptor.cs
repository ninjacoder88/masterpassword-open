using System;
using System.IO;
using System.Security.Cryptography;

namespace MasterPassword.BusinessLogic
{
    public interface IEncryptor
    {
        bool PlainTextMatchesHash(string plainTextValue, string hashedValue);

        string HashEncrypt(string plainTextValue);

        byte[] SymmerticKeyEncrypt(byte[] key, string value);

        string SymmetricKeyDecrypt(byte[] key, byte[] encryptedValue);
    }

    internal sealed class Encryptor : IEncryptor
    {
        private const int Iterations = 10000;

        public bool PlainTextMatchesHash(string plainTextValue, string hashedValue)
        {
            byte[] hashBytes = Convert.FromBase64String(hashedValue);

            byte[] salt = new byte[16];
            Array.Copy(hashBytes, 0, salt, 0, 16);

            var pbkdf2 = new Rfc2898DeriveBytes(plainTextValue, salt, Iterations);
            byte[] hash = pbkdf2.GetBytes(20);

            for (int i = 0; i < 20; i++)
                if (hashBytes[i + 16] != hash[i])
                    return false;

            return true;
        }

        public string HashEncrypt(string plainTextValue)
        {
            byte[] salt = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(salt);
            //RandomNumberGenerator.Fill(salt);

            var pbkdf2 = new Rfc2898DeriveBytes(plainTextValue, salt, Iterations);
            byte[] hash = pbkdf2.GetBytes(20);

            byte[] hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);

            return Convert.ToBase64String(hashBytes);
        }

        public byte[] SymmerticKeyEncrypt(byte[] key, string value)
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var aes = Aes.Create())
                {
                    aes.Key = key;

                    byte[] iv = aes.IV;
                    memoryStream.Write(iv, 0, iv.Length);

                    using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        using (var streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(value);
                        }
                    }
                }

                return memoryStream.ToArray();
            }
        }

        public string SymmetricKeyDecrypt(byte[] key, byte[] encryptedValue)
        {
            using (var memoryStream = new MemoryStream(encryptedValue))
            {
                using (var aes = Aes.Create())
                {
                    byte[] iv = new byte[aes.IV.Length];
                    memoryStream.Read(iv, 0, iv.Length);

                    using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(key, iv), CryptoStreamMode.Read))
                    {
                        using (var streamReader = new StreamReader(cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}
