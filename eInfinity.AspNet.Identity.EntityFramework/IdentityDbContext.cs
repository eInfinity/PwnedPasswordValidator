using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.Entity;
using System.Data.Common;
using System.Data.Entity.Infrastructure;

namespace eInfinity.AspNet.Identity.EntityFramework
{
    public class IdentityDbContext : IdentityDbContext<IdentityUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>
    {

    }
    public class IdentityDbContext<TUser> : IdentityDbContext<TUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>
        where TUser : IdentityUser
    {

    }
    public class IdentityDbContext<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim> : Microsoft.AspNet.Identity.EntityFramework.IdentityDbContext<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim>
        where TUser : IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim>
        where TRole : IdentityRole<TKey, TUserRole>
        where TUserLogin : IdentityUserLogin<TKey>
        where TUserRole : IdentityUserRole<TKey>
        where TUserClaim : IdentityUserClaim<TKey>
    {
        public IdentityDbContext() : this("DefaultConnection") { }
        public IdentityDbContext(string nameOrConnectionString) : base(nameOrConnectionString) { }
        public IdentityDbContext(DbConnection existingConnection, DbCompiledModel model, bool contextOwnsConnection) : base(existingConnection, model, contextOwnsConnection) { }
        public IdentityDbContext(DbCompiledModel model) : base(model) { }
        public IdentityDbContext(DbConnection existingConnection, bool contextOwnsConnection) : base(existingConnection, contextOwnsConnection) { }
        public IdentityDbContext(string nameOrConnectionString, DbCompiledModel model) : base(nameOrConnectionString, model) { }
        public virtual IDbSet<BadPassword> BadPassword { get; set; }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<BadPassword>().HasKey(p => p.PasswordHash);
        }
    }
}
