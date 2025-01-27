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
                // Issuer, neboli "Unikátní URL adresa zabezpečené části Vašeho webu"
                "https://msdocs-core-sql-674-g4b8bgf8e5e3h0bh.westeurope-01.azurewebsites.net/Home/Secured",
                "https://msdocs-core-sql-674-g4b8bgf8e5e3h0bh.westeurope-01.azurewebsites.net/Account/SamlConsume"
            );

            //now send the user to the SAML provider
            return Redirect(request.GetRedirectUrl(samlEndpoint));
        }
        
        public async Task<IActionResult> SamlConsume()
        {
            // 1. TODO: specify the certificate that your SAML provider gave you
            string samlCertificate = @"-----BEGIN CERTIFICATE-----
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
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