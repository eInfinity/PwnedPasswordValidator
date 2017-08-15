using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

namespace eInfinity.AspNet.Identity
{
    public class UserManager<TUser, TKey> : Microsoft.AspNet.Identity.UserManager<TUser, TKey> where TUser : class, IUser<TKey> where TKey : IEquatable<TKey>
    {
        public UserManager(IUserStore<TUser, TKey> store) : base(store)
        {
            BadPasswordHasher = new SHA1PasswordHasher();
        }

        public virtual bool SupportsBadPassword
        {
            get
            {
                return Store is IBadPasswordStore<TUser, TKey>;
            }
        }

        public virtual Task<bool> IsBadPasswordAsync(string password)
        {
            var hash = BadPasswordHasher.HashPassword(password);
            var store = GetBadPasswordStore();

            return store.IsBadPasswordHashAsync(hash);
            
        }

        private IBadPasswordStore<TUser, TKey> GetBadPasswordStore()
        {
            var store = Store as IBadPasswordStore<TUser, TKey>;
            if(store == null)
            {
                throw new NotSupportedException();
            }
            return store;
        }

        public virtual IPasswordHasher BadPasswordHasher
        {
            get;
            set;
        }
    }
}
