namespace DotNetCoreSqlDb.App.Auth;

public enum AbpLoginResultType : byte
{
    Success = 1,

    InvalidUserNameOrEmailAddress,
        
    InvalidPassword,
        
    UserIsNotActive,

    InvalidTenancyName,
        
    TenantIsNotActive,

    UserEmailIsNotConfirmed,
        
    UnknownExternalLogin,

    LockedOut,

    UserPhoneNumberIsNotConfirmed,
        
    FailedForOtherReason
}