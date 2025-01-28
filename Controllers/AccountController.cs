using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Sustainsys.Saml2.AspNetCore2;

namespace DotNetCoreSqlDb.Controllers
{
    public class AccountController : Controller
    {
        [HttpPost]
        public IActionResult Login()
        {
            // Automatic handling is to redirect back to same page after successful
            // login. We don't want that on explicit login.
            var props = new AuthenticationProperties
            {
                RedirectUri = "/"
            };

            return Challenge(props, Saml2Defaults.Scheme);
        }

        [HttpPost]
        public IActionResult Logout()
        {
            var props = new AuthenticationProperties
            {
                RedirectUri = "/"
            };

            // On application initiated signout, it's the application's responsibility
            // to both terminate the local session and issue a remote signout. Always
            // put the cookie scheme first as that requires headers to be written. If the
            // Saml2 logout uses POST binding it will write the body and flush the headers,
            // causing an exception when the cookie handler tries to write headers.
            return SignOut(props, CookieAuthenticationDefaults.AuthenticationScheme, Saml2Defaults.Scheme);
        }
    }
}