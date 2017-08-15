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
    public class HIBPPasswordValidator : AggregateIdentityValidator<string>
    {
        private static string PwnedUrl = @"https://haveibeenpwned.com/api/v2/";

        public int RetryCount { get; set; }
        public IPasswordHasher PasswordHasher { get; set; }

        public HIBPPasswordValidator() : this(null)
        {
        }
        public HIBPPasswordValidator(params IIdentityValidator<string>[] validators) : base(validators)
        {
            RetryCount = 3;
            PasswordHasher = new SHA1PasswordHasher();
        }
        protected override async Task<IList<string>> GetErrorsAsync(string password)
        {
            var errors = await base.GetErrorsAsync(password);

            string passwordHash = PasswordHasher.HashPassword(password);

            using (HttpClient client = new HttpClient())
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                client.BaseAddress = new Uri(PwnedUrl);
                client.DefaultRequestHeaders.Add("User-Agent", typeof(HIBPPasswordValidator).FullName);

                int attempts = RetryCount, delay = 500;
                for (;;)
                {
                    HttpResponseMessage response = null;
                    try
                    {
                        response = await client.GetAsync($"PwnedPassword/{passwordHash}");

                        if (response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.NotFound)
                        {
                            if (response.StatusCode == HttpStatusCode.OK)
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
            return errors;
        }        
    }
}
