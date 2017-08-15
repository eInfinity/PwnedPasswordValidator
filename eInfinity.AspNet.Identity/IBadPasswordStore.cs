using NetIdentity = Microsoft.AspNet.Identity;
using System.Threading.Tasks;

namespace eInfinity.AspNet.Identity
{
    public interface IBadPasswordStore<TUser, in TKey> : NetIdentity.IUserStore<TUser, TKey> where TUser : class, NetIdentity.IUser<TKey>
    {
        Task<bool> IsBadPasswordHashAsync(string hashedPassword);
    }
}
