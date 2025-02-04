using System.Drawing.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace DotNetCoreSqlDb.App.Auth;

public abstract class LogInManagerBase
{
    private readonly UserClaimsPrincipalFactory<IdentityUser> _claimsPrincipalFactory;

    /// <summary>
    /// Constructor.
    /// </summary>
    protected LogInManagerBase(UserClaimsPrincipalFactory<IdentityUser> claimsPrincipalFactory)
    {
        _claimsPrincipalFactory = claimsPrincipalFactory;
    }

    protected virtual async Task<AbpLoginResult> CreateLoginResultAsync(IdentityUser user)
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

public class LogInManager : LogInManagerBase
{
    private readonly UserManager<IdentityUser> _userManager;

    /// <summary>
    /// Constructor.
    /// </summary>
    public LogInManager(UserClaimsPrincipalFactory<IdentityUser> claimsPrincipalFactory, UserManager<IdentityUser> userManager) : base(claimsPrincipalFactory)
    {
        _userManager = userManager;
    }

    public async Task<bool> CanLoginAsync(IdentityUser user)
    {
        if (await _userManager.IsLockedOutAsync(user))
        {
            return false;
        }

        AbpLoginResult loginResult = await CreateLoginResultAsync(user);

        return loginResult.Result == AbpLoginResultType.Success;
    }

    protected override async Task<AbpLoginResult> CreateLoginResultAsync(IdentityUser user)
    {
        var loginResult = await base.CreateLoginResultAsync(user);

        // Not confirmed email address - return user id too.
        if (loginResult.Result == AbpLoginResultType.UserEmailIsNotConfirmed)
        {
            return new AbpLoginResult(loginResult.Result, user);
        }

        return loginResult;
    }

    // ---------


}