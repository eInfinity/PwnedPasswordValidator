using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using eInfinity.AspNet.Identity.Properties;

namespace eInfinity.AspNet.Identity
{
    public class BadPasswordValidator<TUser, TKey> : AggregateIdentityValidator<string> where TUser : class, IUser<TKey> where TKey : IEquatable<TKey>
    {
        UserManager<TUser, TKey> _manager;

        public BadPasswordValidator(UserManager<TUser, TKey> manager) : this(manager, null)
        {

        }
        public BadPasswordValidator(UserManager<TUser, TKey> manager, params IIdentityValidator<string>[] validators) : base(validators)
        {
            _manager = manager;
        }

        protected override async Task<IList<string>> GetErrorsAsync(string password)
        {
            var errors = await base.GetErrorsAsync(password);

            if(await _manager.IsBadPasswordAsync(password))
            {
                errors.Add(Resources.PasswordBreached);
            }

            return errors;
        }

    }
}
