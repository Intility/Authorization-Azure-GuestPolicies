using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using System.Security.Claims;
using Xunit;

namespace Intility.Authorization.Azure.GuestPolicies.Tests.Policy
{
    public class DenyGuestsExtensionsTests
    {
        [Fact]
        public void AddDenyGuestsAuthorization_AddsDenyGuestsAuthorizationsHandler()
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            var result = services.AddDenyGuestsAuthorization();

            // Assert
            Assert.Single(result);
        }

        [Fact]
        public void DenyGuests_Should_AddDenyGuestsAuthorizationRequirement()
        {
            // Arrange
            var authorizationPolicyBuilder = new AuthorizationPolicyBuilder();

            // Act
            authorizationPolicyBuilder.DenyGuests();

            // Assert
            Assert.Contains(authorizationPolicyBuilder.Requirements, x => x.GetType() == typeof(DenyGuestsAuthorizationRequirement));
        }

        [Fact]
        public void FindFirstValue_Should_ReturnNull_When_ClaimTypeIsNotPresent()
        {
            // Arrange
            var principal = Substitute.For<ClaimsPrincipal>();

            // Act
            var result = principal.FindFirstValue("nonexistentClaimType");

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void FindFirstValue_Should_ReturnClaimValue_When_ClaimTypeIsPresent()
        {
            // Arrange
            var principal = Substitute.For<ClaimsPrincipal>();
            var claimType = "testClaimType";
            var claimValue = "testClaimValue";
            principal.FindFirst(claimType).Returns(new Claim(claimType, claimValue));

            // Act
            var result = principal.FindFirstValue(claimType);

            // Assert
            Assert.Equal(claimValue, result);
        }
    }
}
