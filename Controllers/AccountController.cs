using DotNetCoreSqlDb.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Saml;
using System.Diagnostics;
using System.Security.Claims;

namespace DotNetCoreSqlDb.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult NiaLogin()
        {
            var samlEndpoint = "https://tnia.identita.gov.cz/FPSTS/saml2/basic";

            var request = new AuthRequest(
                "DotNetCoreSqlDb",
                "https://opulent-potato-69pxr5p4rjp2rwv6-5093.app.github.dev/Account/SamlConsume"
            );

            //now send the user to the SAML provider
            return Redirect(request.GetRedirectUrl(samlEndpoint));
        }
        
        public async Task<IActionResult> SamlConsume()
        {
            // 1. TODO: specify the certificate that your SAML provider gave you
            string samlCertificate = @"-----BEGIN CERTIFICATE-----
        BLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAH123543==
        -----END CERTIFICATE-----";

            // 2. Let's read the data - SAML providers usually POST it into the "SAMLResponse" var
            var samlResponse = new Response(samlCertificate, Request.Form["SAMLResponse"]);

            // 3. DONE!
            if (samlResponse.IsValid()) //all good?
            {
                //WOOHOO!!! the user is logged in
                var username = samlResponse.GetNameID(); //let's get the username
                
                //the user has been authenticated
                //now call context.SignInAsync() for ASP.NET Core
                //or call FormsAuthentication.SetAuthCookie() for .NET Framework
                //or do something else, like set a cookie or something...
                
                //FOR EXAMPLE this is how you sign-in a user in ASP.NET Core 3,5,6,7
                this.HttpContext.User = new ClaimsPrincipal(
                    new ClaimsIdentity(
                        [new Claim(ClaimTypes.Name, username)],
                        CookieAuthenticationDefaults.AuthenticationScheme));
                // await context.SignInAsync(new ClaimsPrincipal(
                //     new ClaimsIdentity(
                //         new[] { new Claim(ClaimTypes.Name, username) },
                //         CookieAuthenticationDefaults.AuthenticationScheme)));
                
                return Redirect("~/");
            }
            
            return Content("Unauthorized");
        }
    }
}