using Microsoft.AspNetCore.Authorization;

namespace Intility.Authorization.Azure.GuestPolicies;

/// <summary>
/// Implements an <see cref="IAuthorizationRequirement"/>
/// which requires the current user to be a member of the tenant.
/// </summary>
public class DenyGuestsAuthorizationRequirement : IAuthorizationRequirement { }

