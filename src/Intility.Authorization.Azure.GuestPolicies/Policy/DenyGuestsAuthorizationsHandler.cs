using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace Intility.Authorization.Azure.GuestPolicies;

/// <summary>
/// Denies authorization for guests.
/// </summary>
public class DenyGuestsAuthorizationsHandler : AuthorizationHandler<DenyGuestsAuthorizationRequirement>
{
    private const string IdentityProvider = "http://schemas.microsoft.com/identity/claims/identityprovider";
    private const string Idp = "idp";
    private const string Iss = "iss";
    private const string Acct = "acct";
    private const string TenantMember = "0";

    /// <summary>
    /// Makes a decision if authorization is allowed based on a specific requirement.
    /// </summary>
    /// <param name="context">AuthorizationHandlerContext.</param>
    /// <param name="requirement">Deny Guests authorization requirement.</param>
    /// <returns>Task.</returns>
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, DenyGuestsAuthorizationRequirement requirement)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requirement);

        // acct is an optional claim
        // if it is present, it dictates whether the user is a guest or not
        var acct = context.User.FindFirstValue(Acct);

        if (!string.IsNullOrEmpty(acct))
        {
            if (acct == TenantMember)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }

        // if acct is not present
        // we can use the iss and idp claim to determine if the user is a guest
        var iss = context.User.FindFirstValue(Iss);
        var idp = GetIdentityProvider(context.User, iss);

        if (!string.IsNullOrEmpty(iss) && iss == idp)
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        return Task.CompletedTask;
    }

    private static string? GetIdentityProvider(ClaimsPrincipal claimsPrincipal, string? issuer)
    {
        return claimsPrincipal.FindFirstValue(IdentityProvider) ?? claimsPrincipal.FindFirstValue(Idp) ?? issuer;
    }
}

/// <summary>
/// Contains extension methods for denying guests.
/// </summary>
public static class DenyGuestsAuthorizationExtensions
{
    /// <summary>
    /// Adds a requirement to the policy builder that denies guests.
    /// </summary>
    /// <param name="builder">The authorization policy builder.</param>
    /// <returns>The same builder instance.</returns>
    public static AuthorizationPolicyBuilder DenyGuests(this AuthorizationPolicyBuilder builder)
    {
        builder.AddRequirements(new DenyGuestsAuthorizationRequirement());
        return builder;
    }
}
