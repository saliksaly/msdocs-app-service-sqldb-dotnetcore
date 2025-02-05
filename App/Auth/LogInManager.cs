using DotNetCoreSqlDb.App.Auth.Entities;
using Microsoft.AspNetCore.Identity;

namespace DotNetCoreSqlDb.App.Auth;

public class LogInManager : LogInManagerBase
{
    private readonly UserManager<ApplicationUser> _userManager;

    /// <summary>
    /// Constructor.
    /// </summary>
    public LogInManager(UserClaimsPrincipalFactory<ApplicationUser> claimsPrincipalFactory, UserManager<ApplicationUser> userManager) 
        : base(claimsPrincipalFactory)
    {
        _userManager = userManager;
    }

    public async Task<bool> CanLoginAsync(ApplicationUser user)
    {
        if (await _userManager.IsLockedOutAsync(user))
        {
            return false;
        }

        AbpLoginResult loginResult = await CreateLoginResultAsync(user);

        return loginResult.Result == AbpLoginResultType.Success;
    }

    protected override async Task<AbpLoginResult> CreateLoginResultAsync(ApplicationUser user)
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