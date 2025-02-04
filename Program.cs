using System.Security.Claims;
using DotNetCoreSqlDb.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Sustainsys.Saml2;
using Sustainsys.Saml2.AspNetCore2;
using Sustainsys.Saml2.Metadata;
using System.Security.Cryptography.X509Certificates;
using DotNetCoreSqlDb.Controllers;
using Microsoft.AspNetCore.Identity;

var builder = WebApplication.CreateBuilder(args);

// Add database context and cache
if(builder.Environment.IsDevelopment())
{
    builder.Services.AddDbContext<MyDatabaseContext>(options =>
        options.UseSqlServer(builder.Configuration.GetConnectionString("MyDbConnection")));
    builder.Services.AddDistributedMemoryCache();
}
else
{
    builder.Services.AddDbContext<MyDatabaseContext>(options =>
        options.UseSqlServer(builder.Configuration.GetConnectionString("AZURE_SQL_CONNECTIONSTRING")));
    // builder.Services.AddStackExchangeRedisCache(options =>
    // {
    //     options.Configuration = builder.Configuration["AZURE_REDIS_CONNECTIONSTRING"];
    //     options.InstanceName = "SampleInstance";
    // });
}

// Add Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
    {
        options.Password.RequireDigit = true;
        options.Password.RequiredLength = 6;
        options.Password.RequireNonAlphanumeric = false;
    })
    .AddEntityFrameworkStores<MyDatabaseContext>()
    .AddDefaultTokenProviders();

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddAuthentication()
    //.AddCookie()
    .AddSaml2("NIA", opt =>
    {
        // Set up our EntityId, this is our application.
        //opt.SPOptions.EntityId = new EntityId("http://localhost:5093/Saml2");
        opt.SPOptions.EntityId = new EntityId("https://localhost:7291/Saml2");

        // Single logout messages should be signed according to the SAML2 standard, so we need
        // to add a certificate for our app to sign logout messages with to enable logout functionality.
        opt.SPOptions.ServiceCertificates.Add(new X509Certificate2("app.pfx"));

        // Add an identity provider.
        opt.IdentityProviders.Add(
            new IdentityProvider(
                // The identityprovider's entity id.
                //new EntityId("https://stubidp.sustainsys.com/Metadata"),
                new EntityId(
                    // SusitainSys:
                    "https://stubidp.sustainsys.com/Metadata"),
                // NIA testovací:
                //"https://tnia.identitaobcana.cz/fpsts/FederationMetadata/2007-06/FederationMetadata.xml"),
                // NIA produkční:
                // https://nia.identitaobcana.cz/fpsts/FederationMetadata/2007-06/FederationMetadata.xml"),
                opt.SPOptions)
            {
                // Load config parameters from metadata, using the Entity Id as the metadata address.
                LoadMetadata = true,

                //SingleSignOnServiceUrl = null,
                //SingleLogoutServiceUrl = null,
                //SingleLogoutServiceResponseUrl = null,
                //SingleLogoutServiceBinding = (Saml2BindingType)0,

                //MetadataLocation = null,
                //RelayStateUsedAsReturnUrl = false,
                //WantAuthnRequestsSigned = false, // v produkci ano?
            });

        // Transform claims using a callback/notification. This is the simplest way to transform
        // claims, but there is no way to show UI and there is no access to other services.
        // Inspired here: https://github.com/Sustainsys/Saml2.Samples/blob/main/v2/AspNetCoreClaimsTransformation/Program.cs
        opt.Notifications.AcsCommandResultCreated = (commandResult, response) =>
        {
            ClaimsIdentity identity = commandResult.Principal.Identities.Single();

            // We want modern/OIDC-style "sub" claim and not http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier

            Claim nameIdClaim = identity.FindFirst(ClaimTypes.NameIdentifier)
                                ?? throw new InvalidOperationException("There should always be a NameId in a Saml2 response.");

            identity.AddClaim(
                new Claim(AccountController.CommonClaimTypes.Subject, nameIdClaim.Value));

            // Email claim

            Claim storkEmailClaim = identity.FindFirst(AccountController.NiaClaimTypes.Email);
            if (storkEmailClaim != null)
            {
                identity.AddClaim(
                    new Claim(AccountController.CommonClaimTypes.Email, storkEmailClaim.Value));
            }

            // Also put the somewhat hard to find Idp entity id into a claim by itself.

            identity.AddClaim(
                new Claim(AccountController.CommonClaimTypes.IdentityProvider, nameIdClaim.Issuer));
        };
    });

// Add App Service logging
builder.Logging.AddAzureWebAppDiagnostics();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Todos}/{action=Index}/{id?}");

app.Run();