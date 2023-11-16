using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Security.Claims;

namespace Intility.Authorization.Azure.GuestPolicies;

/// <summary>
/// Extensions for building the deny guest requirement during application startup.
/// </summary>
public static class DenyGuestsExtensions
{
    /// <summary>
    /// This method adds support for the deny guests requirement.
    /// </summary>
    /// <param name="services">The services being configured.</param>
    /// <returns>Services.</returns>
    public static IServiceCollection AddDenyGuestsAuthorization(this IServiceCollection services)
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthorizationHandler, DenyGuestsAuthorizationsHandler>());

        return services;
    }

    /// <summary>
    /// Adds a <see cref="DenyGuestsAuthorizationRequirement"/> to the current instance which requires that the current user is a member of the tenant.
    /// </summary>
    /// <param name="authorizationPolicyBuilder">Used for building policies during application startup.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public static AuthorizationPolicyBuilder DenyGuests(this AuthorizationPolicyBuilder authorizationPolicyBuilder)
    {
        ArgumentNullException.ThrowIfNull(authorizationPolicyBuilder);

        authorizationPolicyBuilder.Requirements.Add(new DenyGuestsAuthorizationRequirement());

        return authorizationPolicyBuilder;
    }

    /// <summary>
    /// Returns the value for the first claim of the specified type, otherwise null if the claim is not present.
    /// </summary>
    /// <param name="principal">The <see cref="ClaimsPrincipal"/> instance this method extends.</param>
    /// <param name="claimType">The claim type whose first value should be returned.</param>
    /// <returns>The value of the first instance of the specified claim type, or null if the claim is not present.</returns>
    internal static string? FindFirstValue(this ClaimsPrincipal principal, string claimType)
    {
        ArgumentNullException.ThrowIfNull(principal);
        var claim = principal.FindFirst(claimType);
        return claim?.Value;
    }
}
