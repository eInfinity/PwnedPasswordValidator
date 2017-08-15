using eInfinity.AspNet.Identity.Properties;
using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace eInfinity.AspNet.Identity
{
    public class PwnedPasswordValidator : IIdentityValidator<string>
    {
        private static string PwnedUrl = @"https://haveibeenpwned.com/api/v2/";
        IIdentityValidator<string>[] _validators;

        public int RetryCount { get; set; }

        public PwnedPasswordValidator()
        {
            RetryCount = 3;
        }
        public PwnedPasswordValidator(params IIdentityValidator<string>[] validators) : this()
        {
            _validators = validators;
        }

        public async Task<IdentityResult> ValidateAsync(string password)
        {
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }
            var errors = new List<string>();
            if (_validators != null && _validators.Length > 0)
            {
                foreach (var validator in _validators)
                {
                    var result = await validator.ValidateAsync(password);
                    if (!result.Succeeded)
                    {
                        errors.AddRange(result.Errors);
                    }
                }
            }

            string passwordHash = ComputeHash(password);

            using (HttpClient client = new HttpClient())
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                client.BaseAddress = new Uri(PwnedUrl);
                client.DefaultRequestHeaders.Add("User-Agent", typeof(PwnedPasswordValidator).FullName);

                int attempts = RetryCount, delay = 500;
                for (;;)
                {
                    HttpResponseMessage response = null;
                    try
                    {
                        response = await client.GetAsync($"PwnedPassword/{passwordHash}");

                        if (response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.NotFound)
                        {
                            if(response.StatusCode == HttpStatusCode.OK)
                            {
                                errors.Add(Resources.PasswordBreached);
                            }
                            break;
                        }
                    }
                    catch (Exception ex)
                    {
                        Trace.Write(ex);
                    }
                    finally
                    {
                        if (response != null)
                            response.Dispose();
                    }
                    attempts--;
                    if (attempts <= 0)
                    {
                        errors.Add(Resources.MaxRetriesReached);
                        break;
                    }
                    await Task.Delay(delay);
                }
            }
            return errors.Count == 0 ? IdentityResult.Success : IdentityResult.Failed(errors.ToArray());
        }

        private string ComputeHash(string password)
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(password);
                byte[] hash = sha1.ComputeHash(bytes);

                StringBuilder passwordHash = new StringBuilder();
                foreach(byte b in hash)
                {
                    passwordHash.AppendFormat("{0:x2}", b);
                }
                return passwordHash.ToString();
            }
        }
    }
}
