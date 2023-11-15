using Microsoft.AspNetCore.Authorization;

namespace Intility.Authorization.Azure.GuestPolicies;

/// <summary>
/// Extensions for building the RequiredScope policy during application startup.
/// </summary>
public static class PolicyBuilderExtensions
{
    /// <summary>
    /// Adds a <see cref="DenyGuestsAuthorizationRequirement"/> to the current instance which requires
    /// that the current user is a member of the tenant.
    /// </summary>
    /// <param name="authorizationPolicyBuilder">Used for building policies during application startup.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public static AuthorizationPolicyBuilder DenyGuests(this AuthorizationPolicyBuilder authorizationPolicyBuilder)
    {
        ArgumentNullException.ThrowIfNull(authorizationPolicyBuilder);

        authorizationPolicyBuilder.Requirements.Add(new DenyGuestsAuthorizationRequirement());

        return authorizationPolicyBuilder;
    }
}
