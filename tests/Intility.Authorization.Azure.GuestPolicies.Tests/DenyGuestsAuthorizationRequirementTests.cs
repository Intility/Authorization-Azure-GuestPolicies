using Intility.Authorization.Azure.GuestPolicies.Tests.Common;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Xunit;

namespace Intility.Authorization.Azure.GuestPolicies.Tests
{
    public class DenyGuestsAuthorizationRequirementTests
    {
        private readonly DenyGuestsAuthorizationsHandler _handler = new();

        private const string IdentityProvider = "http://schemas.microsoft.com/identity/claims/identityprovider";
        private const string Idp = "idp";
        private const string Iss = "iss";
        private const string Acct = "acct";

        private const string GuestIdentityProvider = $"https://sts.windows.net/fbcdbb10-816a-4443-953e-d556d2ba0df7/";

        [Fact]
        public async Task DenyGuestsPolicy_TenantMembersWithAcctClaim_SucceedsAsync()
        {
            // Arrange
            var user = CreateClaimsPrincipal(new Claim[] { new(Acct, "0") });

            var context = CreateAuhtorizationHandlerContext(user);

            // Act
            await _handler.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
        }

        [Fact]
        public async Task DenyGuestsPolicy_GuestUsersWithAcctClaim_FailsAsync()
        {
            // Arrange
            var user = CreateClaimsPrincipal(new Claim[] { new(Acct, "1") });

            var context = CreateAuhtorizationHandlerContext(user);

            // Act
            await _handler.HandleAsync(context);

            // Assert
            Assert.False(context.HasSucceeded);
        }

        // V1 Application Tokens
        // Test both with and without idp transformation
        [Theory]
        [InlineData(Idp)]
        [InlineData(IdentityProvider)]
        public async Task DenyGuestPolicy_V1ApplicationTokens_SucceedsAsync(string idpClaimName)
        {
            // Arrange 
            // V1 Application Tokens includes both IDP and Issuer with the same value
            var user = CreateClaimsPrincipal(new Claim[]
            {
                new(Iss, TestConstants.V1Issuer),
                new(idpClaimName, TestConstants.V1Issuer)
            });

            var context = CreateAuhtorizationHandlerContext(user);

            // Act
            await _handler.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
        }

        // V2 Application Tokens
        [Fact]
        public async Task DenyGuestPolicy_V2ApplicationTokens_SucceedsAsync()
        {
            // Arrange 
            // V2 Application Tokens does not contain the IDP claim
            var user = CreateClaimsPrincipal(new Claim[]
            {
                new(Iss, TestConstants.AadIssuer)
            });

            var context = CreateAuhtorizationHandlerContext(user);

            // Act
            await _handler.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
        }

        // Tenant Members
        // This should work with both v1 and v2 issuer
        [Theory]
        [InlineData(TestConstants.AadIssuer)]
        [InlineData(TestConstants.V1Issuer)]
        public async Task DenyGuestPolicy_TenantMemberTokens_SucceedsAsync(string issuer)
        {
            // Arrange 
            // Tenant Member Tokens does not contain the IDP claim in either version
            var user = CreateClaimsPrincipal(new Claim[]
            {
                new(Iss, issuer)
            });

            var context = CreateAuhtorizationHandlerContext(user);

            // Act
            await _handler.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
        }

        // Guest Users
        // Test both token versions with and without idp transformation
        [Theory]
        [InlineData(TestConstants.AadIssuer, Idp)]
        [InlineData(TestConstants.AadIssuer, IdentityProvider)]
        [InlineData(TestConstants.V1Issuer, Idp)]
        [InlineData(TestConstants.V1Issuer, IdentityProvider)]
        public async Task DenyGuestPolicy_GuestUserTokens_FailsAsync(string issuer, string idpClaimName)
        {
            // Arrange 
            var user = CreateClaimsPrincipal(new Claim[]
            {
                new(Iss, issuer),
                // The guest IDP is the same in both versions
                new(idpClaimName, GuestIdentityProvider)
            });

            var context = CreateAuhtorizationHandlerContext(user);

            // Act
            await _handler.HandleAsync(context);

            // Assert
            Assert.False(context.HasSucceeded);
        }

        private static ClaimsPrincipal CreateClaimsPrincipal(IEnumerable<Claim> claims)
        {
            return new ClaimsPrincipal(new ClaimsIdentity(claims));
        }

        private static AuthorizationHandlerContext CreateAuhtorizationHandlerContext(ClaimsPrincipal user)
        {
            var requirement = new DenyGuestsAuthorizationRequirement();
            return new AuthorizationHandlerContext(new[] { requirement }, user, null);
        }
    }
}

