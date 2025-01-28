using System.Security.Claims;

namespace DotNetCoreSqlDb.Models.Home;

public class SecuredModel(IDictionary<string, string?> properties, IEnumerable<Claim> claims)
{
    public IDictionary<string, string?> Properties { get; } = properties;
    public IEnumerable<Claim> Claims { get; } = claims;
}