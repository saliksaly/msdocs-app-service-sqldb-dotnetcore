using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using NuGet.Protocol.Plugins;
using Sustainsys.Saml2.AspNetCore2;
using System.Security.Claims;
using DotNetCoreSqlDb.App.Auth;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;
using DotNetCoreSqlDb.App.Auth.Entities;

namespace DotNetCoreSqlDb.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly LogInManager _logInManager;

        /// <summary>
        /// Constructor.
        /// </summary>
        public AccountController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, LogInManager logInManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logInManager = logInManager;
        }

        //[HttpGet]
        //public async Task<IActionResult> Login(string returnUrl)
        //{
        //    var externalAuthSchemes = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
        //}

        [HttpGet]
        //[HttpPost]
        public IActionResult Login(string? returnUrl = null)
        {
            return ExternalLogin("NIA", returnUrl);

            //// Automatic handling is to redirect back to same page after successful
            //// login. We don't want that on explicit login.
            //var props = new AuthenticationProperties
            //{
            //    RedirectUri = "/"
            //};

            //return Challenge(props, "NIA");
        }

        [HttpGet]
        public IActionResult ExternalLogin(string authScheme, string? returnUrl = null)
        {
            returnUrl ??= "/";

            if(!Url.IsLocalUrl(returnUrl))
            {
                throw new InvalidOperationException("Open redirect protection");
            }
            
            // External Identity Provider with ASP.NET Core Identity - Code Maze
            // https://code-maze.com/external-identity-provider-aspnet-core-identity/

            string redirectUrl = Url.Action(nameof(ExternalLoginCallback), new { returnUrl })!;

            AuthenticationProperties properties = _signInManager.ConfigureExternalAuthenticationProperties(authScheme, redirectUrl);

            // We return a challenge. With it, we challenge a user to provide an identity supplied by the provider.

            return Challenge(properties, authScheme);
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

        #region External login

        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null)
        {
            returnUrl ??= "/";


            // Get information about the user from the external provider.

            ExternalLoginInfo? externalLoginInfo = await _signInManager.GetExternalLoginInfoAsync();
            
            if (externalLoginInfo == null)
            {
                return Unauthorized("External login failed");
            }


            // Try external sign in

            SignInResult signInResult = await _signInManager.ExternalLoginSignInAsync(externalLoginInfo.LoginProvider, externalLoginInfo.ProviderKey, isPersistent: false, bypassTwoFactor: true);

            if (signInResult.Succeeded)
            {
                AddExternalProviderIdentityToCurrentUser(externalLoginInfo);

                return Redirect(returnUrl);
            }

            if (signInResult.IsLockedOut)
            {
                return Unauthorized("User is locked out.");
            }

            if (signInResult.IsNotAllowed)
            {
                return Unauthorized("User is not allowed to sign-in.");
            }    


            // Treat non-existing user with external login

            return await TreatNewExternalLoginAsync(externalLoginInfo, returnUrl);
        }

        private async Task<IActionResult> TreatNewExternalLoginAsync(ExternalLoginInfo externalLoginInfo, string returnUrl)
        {
            bool? canLinkUserByEmail = true;

            if (User.Identity is { IsAuthenticated: true })
            {
                // User is logged in.

                ApplicationUser user = await _userManager.GetUserAsync(User) 
                            ?? throw new InvalidOperationException();

                var logins = await _userManager.GetLoginsAsync(user);

                if (logins.Any(x => x.LoginProvider == externalLoginInfo.LoginProvider))
                {
                    // Is n NIA user (but different identity because the same would be logged in above).

                    throw new InvalidOperationException("Current logged user is mapped to another external authentication provider.");
                }

                // Is not NIA user.

                await AddExternalLoginToCurrentUserAsync(user, externalLoginInfo);
                
                AddExternalProviderIdentityToCurrentUser(externalLoginInfo);

                return Redirect(returnUrl);
            }

            string? emailAddress = externalLoginInfo.Principal.FindFirstValue(CommonClaimTypes.Email);

            if (emailAddress != null)
            {
                // Email address is present in external login claims.

                ApplicationUser? user = await _userManager.FindByEmailAsync(emailAddress);

                if (user != null)
                {
                    if (await _logInManager.CanLoginAsync(user))
                    {
                        switch (canLinkUserByEmail)
                        {
                            case null:

                                // Show choice to user: Link the found user or create new user?

                                throw new NotImplementedException();

                                //const string viewName = "ExternalLoginConfirmLinkUserByEmail";

                                //string nameToModel = "xxx"; // TODO: from resources

                                //string yesUrl = Url.Action(nameof(ExternalLoginCallback),
                                //    new { returnUrl, canLinkUserByEmail = true });

                                //string noUrl = Url.Action(nameof(ExternalLoginCallback),
                                //    new { returnUrl, canLinkUserByEmail = false });

                                //BasicObjectViewModel viewModel = await CreateBasicObjectViewModelAsync(nameToModel);

                                //viewModel.Data.Add("yesUrl", yesUrl);
                                //viewModel.Data.Add("noUrl", noUrl);

                                //return X(viewName, viewModel);

                                break;

                            case true:

                                // Link the external user to the found user.

                                await _signInManager.SignInAsync(user, isPersistent: false);

                                await AddExternalLoginToCurrentUserAsync(user, externalLoginInfo);
                
                                AddExternalProviderIdentityToCurrentUser(externalLoginInfo);

                                break;

                            case false:

                                // Create new user linked to the external user.

                                await CreateUserWithoutEmailAsync(externalLoginInfo);

                                await _signInManager.SignInAsync(user, isPersistent: false);

                                await AddExternalLoginToCurrentUserAsync(user, externalLoginInfo);
                
                                AddExternalProviderIdentityToCurrentUser(externalLoginInfo);

                                break;
                        }
                    }
                    else
                    {
                        // Registrovat uživatele místo emailu s nìjakým náhodným identifikátorem nebo id z NIA.

                        await CreateUserWithoutEmailAsync(externalLoginInfo);

                        await _signInManager.SignInAsync(user, isPersistent: false);

                        await AddExternalLoginToCurrentUserAsync(user, externalLoginInfo);
                
                        AddExternalProviderIdentityToCurrentUser(externalLoginInfo);
                    }
                }
                else
                {
                    // Vytvoøit uživatele - ala Zkrácená registrace

                    user = await CreateUserWithEmailAsync(emailAddress, externalLoginInfo);

                    await _signInManager.SignInAsync(user, isPersistent: false);

                    await AddExternalLoginToCurrentUserAsync(user, externalLoginInfo);
                
                    AddExternalProviderIdentityToCurrentUser(externalLoginInfo);
                }
            }
            else
            {
                ApplicationUser user = await CreateUserWithoutEmailAsync(externalLoginInfo);

                await _signInManager.SignInAsync(user, isPersistent: false);

                await AddExternalLoginToCurrentUserAsync(user, externalLoginInfo);
                
                AddExternalProviderIdentityToCurrentUser(externalLoginInfo);
            }

            return Redirect(returnUrl);
        }

        private async Task<ApplicationUser> CreateUserWithoutEmailAsync(ExternalLoginInfo externalLoginInfo)
        {
            UserInfo userInfo = GetUserInfo(externalLoginInfo);

            string userName = GetUserNameFromUserId(userInfo.Id, externalLoginInfo);

            string emailAddress = $"{userName}@nia.vismo.cz";

            ApplicationUser user = await CreateUserWithEmailAsync(emailAddress, externalLoginInfo);

            user.UserName = userName;

            return user;
        }

        private async Task<ApplicationUser> CreateUserWithEmailAsync(string emailAddress, ExternalLoginInfo externalLoginInfo)
        {
            var user = new ApplicationUser
            {
                UserName = emailAddress,
                Email = emailAddress,
                
                //IsActive = true,
                //IsEmailConfirmed = isEmailConfirmed,
                //IsLegalGuardianEmailConfirmed = false,
                //Roles = new List<UserRole>(),
                //Is16YearsOld = is16YearsOld,
                //AbpLanguageId = languageId
            };

            var identityResult = await _userManager.CreateAsync(user);

            if (!identityResult.Succeeded)
            {
                throw new Exception(identityResult.Errors.First().Description);
            }

            //user.IsRegisteredViaAA = true;
            //user.AuthenticationSource = externalLoginInfo.LoginProvider;
            //user.IsEmailConfirmed = true;

            UserInfo userInfo = GetUserInfo(externalLoginInfo);

            if (userInfo.Name != null)
            {
                user.Name = userInfo.Name;
            }

            if (userInfo.Surname != null)
            {
                user.Surname = userInfo.Surname;
            }

            return user;
        }

        private string GetUserNameFromUserId(string userId, ExternalLoginInfo externalLoginInfo)
        {
            if (externalLoginInfo.LoginProvider == "NIA")
            {
                // CZ/CZ/1x3953xx-7e0d-47xx-8fee2ea231a58ee6
                return userId.Replace('/', '_');
            }

            return userId;
        }

        private UserInfo GetUserInfo(ExternalLoginInfo externalLoginInfo)
        {
            string id = externalLoginInfo.Principal.FindFirstValue(CommonClaimTypes.Subject)
                        ?? throw new InvalidOperationException(
                            $"Missing id claim: {CommonClaimTypes.Subject}");

            if (externalLoginInfo.LoginProvider == "NIA")
            {
                string name = externalLoginInfo.Principal.FindFirstValue(NiaClaimTypes.CurrentGivenName)
                              ?? throw new InvalidOperationException(
                                  $"Missing name claim: {NiaClaimTypes.CurrentGivenName}");

                string surname = externalLoginInfo.Principal.FindFirstValue(NiaClaimTypes.CurrentFamilyName)
                                 ?? throw new InvalidOperationException(
                                     $"Missing surname claim: {NiaClaimTypes.CurrentFamilyName}");

                return new UserInfo(id, name, surname);
            }


            // TODO: jiny login provider treba ani name a surname nepredava.

            throw new NotImplementedException($"Unsupported login provider: {externalLoginInfo.LoginProvider}");
        }

        private void AddExternalProviderIdentityToCurrentUser(ExternalLoginInfo externalLoginInfo)
        {
            var claims = new List<Claim>
            {
                //new Claim("SomeClaim", "SomeValue")
            };

            claims.AddRange(externalLoginInfo.Principal.Claims);

            var externalIdentity = new ClaimsIdentity(claims, externalLoginInfo.LoginProvider);

            //appIdentity.AddClaim(new Claim(ClaimTypes.Name, externalLoginInfo.LoginProvider));

            User.AddIdentity(externalIdentity);
        }

        private async Task AddExternalLoginToCurrentUserAsync(ApplicationUser user, ExternalLoginInfo externalLoginInfo)
        {
            await _userManager.AddLoginAsync(user , externalLoginInfo);
        }

        #endregion

        // -----------------

        private record UserInfo(string Id, string? Name, string? Surname);

        public static class CommonClaimTypes // TODO: presun nekam kam to patri
        {
            /// <summary>
            /// In OpenID Connect (OIDC) and OAuth 2.0, "sub" is a standardized claim representing the subject (unique user identifier).
            /// </summary>
            public const string Subject = JwtRegisteredClaimNames.Sub;

            /// <summary>
            /// Email address
            /// </summary>
            public const string Email = JwtRegisteredClaimNames.Email;

            /// <summary>
            /// Identity provider
            /// </summary>
            public const string IdentityProvider = "http://schemas.microsoft.com/identity/claims/identityprovider";
        }

        public static class NiaClaimTypes // TODO: presun nekam kde jsou NIA veci
        {
            /// <summary>
            /// Jméno
            /// </summary>
            public const string CurrentGivenName = "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName";

            /// <summary>
            /// Pøíjmení
            /// </summary>
            public const string CurrentFamilyName = "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName";

            /// <summary>
            /// Datum narození
            /// </summary>
            public const string DateOfBirth = "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth";

            /// <summary>
            /// Místo narození
            /// </summary>
            public const string PlaceOfBirth = "http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth";

            /// <summary>
            /// Adresa pobytu
            /// </summary>
            public const string CurrentAddress = "http://eidas.europa.eu/attributes/naturalperson/CurrentAddress";

            /// <summary>
            /// E-mail
            /// </summary>
            public const string Email = "http://www.stork.gov.eu/1.0/eMail";

            /// <summary>
            /// Telefon
            /// </summary>
            public const string PhoneNumber = "http://schemas.eidentita.cz/moris/2016/identity/claims/phonenumber";

            /// <summary>
            /// Pseudonym
            /// </summary>
            public const string PersonIdentifier = "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier";
        }
    }
}