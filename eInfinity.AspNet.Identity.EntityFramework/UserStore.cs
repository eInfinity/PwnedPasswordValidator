using NetIdentity = Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.Entity;

namespace eInfinity.AspNet.Identity.EntityFramework
{
    public class UserStore<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim> :NetIdentity.UserStore<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim> where TKey : IEquatable<TKey>,
        IBadPasswordStore<TUser, TKey>     
        where TUser : NetIdentity.IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>
        where TRole : NetIdentity.IdentityRole<TKey, TUserRole>
        where TUserLogin : NetIdentity.IdentityUserLogin<TKey>, new()
        where TUserRole : NetIdentity.IdentityUserRole<TKey>, new()
        where TUserClaim : NetIdentity.IdentityUserClaim<TKey>, new()
    {
        private readonly IDbSet<BadPassword> _badPasswords;
        public UserStore(DbContext context) : base(context)
        {
            _badPasswords = context.Set<BadPassword>();
        }
        public async Task<bool> IsBadPasswordHashAsync(string password)
        {
            return await _badPasswords.AnyAsync(p => p.PasswordHash.Equals(password));
        }
    }
}
