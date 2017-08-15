using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace eInfinity.AspNet.Identity
{
    public class SHA1PasswordHasher : IPasswordHasher
    {
        public string HashPassword(string password)
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(password);
                byte[] hash = sha1.ComputeHash(bytes);

                StringBuilder passwordHash = new StringBuilder();
                foreach (byte b in hash)
                {
                    passwordHash.AppendFormat("{0:x2}", b);
                }
                return passwordHash.ToString();
            }
        }

        public PasswordVerificationResult VerifyHashedPassword(string hashedPassword, string providedPassword)
        {
            string hashedProvidedPassword = HashPassword(providedPassword);

            if(hashedPassword.Equals(hashedProvidedPassword))
            {
                return PasswordVerificationResult.Success;
            }
            return PasswordVerificationResult.Failed;
        }
    }
}
