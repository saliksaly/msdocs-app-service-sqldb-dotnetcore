using Microsoft.AspNetCore.Identity;

namespace DotNetCoreSqlDb.App.Auth.Entities;

public class ApplicationUser : IdentityUser
{
    public string? Name { get; set; }
    public string? Surname { get; set; }
}