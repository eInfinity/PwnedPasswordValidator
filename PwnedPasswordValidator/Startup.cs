using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(PwnedPasswordValidator.Startup))]
namespace PwnedPasswordValidator
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
