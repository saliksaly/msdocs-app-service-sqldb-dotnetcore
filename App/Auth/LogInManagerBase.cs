using System.Security.Claims;
using DotNetCoreSqlDb.App.Auth.Entities;
using Microsoft.AspNetCore.Identity;

namespace DotNetCoreSqlDb.App.Auth;

public abstract class LogInManagerBase
{
    private readonly UserClaimsPrincipalFactory<ApplicationUser> _claimsPrincipalFactory;

    /// <summary>
    /// Constructor.
    /// </summary>
    protected LogInManagerBase(UserClaimsPrincipalFactory<ApplicationUser> claimsPrincipalFactory)
    {
        _claimsPrincipalFactory = claimsPrincipalFactory;
    }

    protected virtual async Task<AbpLoginResult> CreateLoginResultAsync(ApplicationUser user)
    {
        //if (!user.IsActive)
        //{
        //    return new AbpLoginResult<TTenant, TUser>(AbpLoginResultType.UserIsNotActive);
        //}

        //if (await IsEmailConfirmationRequiredForLoginAsync(user.TenantId) && !user.IsEmailConfirmed)
        //{
        //    return new AbpLoginResult<TTenant, TUser>(AbpLoginResultType.UserEmailIsNotConfirmed);
        //}

        //if (await IsPhoneConfirmationRequiredForLoginAsync(user.TenantId) && !user.IsPhoneNumberConfirmed)
        //{
        //    return new AbpLoginResult<TTenant, TUser>(AbpLoginResultType.UserPhoneNumberIsNotConfirmed);
        //}

        ClaimsPrincipal principal = await _claimsPrincipalFactory.CreateAsync(user);

        return new AbpLoginResult(
            user,
            principal.Identity as ClaimsIdentity ?? throw new Exception("Is not ClaimsIdentity.")
        );
    }

    // ---------


}