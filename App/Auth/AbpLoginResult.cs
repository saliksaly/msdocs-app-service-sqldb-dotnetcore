using System.Security.Claims;
using DotNetCoreSqlDb.App.Auth.Entities;
using Microsoft.AspNetCore.Identity;

namespace DotNetCoreSqlDb.App.Auth;

public class AbpLoginResult
{
    public AbpLoginResultType Result { get; private set; }

    public string FailReason { get; private set; }
        
    public ApplicationUser User { get; private set; }

    public ClaimsIdentity Identity { get; private set; }

    public AbpLoginResult(AbpLoginResultType result, ApplicationUser user = null)
    {
        Result = result;
        User = user;
    }

    public AbpLoginResult(ApplicationUser user, ClaimsIdentity identity)
        : this(AbpLoginResultType.Success)
    {
        User = user;
        Identity = identity;
    }

    /// <summary>
    /// This method can be used only when <see cref="Result"/> is <see cref="AbpLoginResultType.FailedForOtherReason"/>.
    /// </summary>
    /// <param name="failReason">Localizable fail reason message</param>
    public void SetFailReason(string failReason)
    {
        if (Result != AbpLoginResultType.FailedForOtherReason)
        {
            throw new Exception($"Can not set fail reason for result type {Result}, use this method only for AbpLoginResultType.FailedForOtherReason result type!");
        }
            
        FailReason = failReason;
    }
}