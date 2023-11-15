namespace Intility.Authorization.Azure.GuestPolicies.Tests.Common;

public static class TestConstants
{
    public const string TenantId = "dcaaf043-1d54-42a3-ad69-b302ecca3d29";
    public const string V1Issuer = $"https://sts.windows.net/{TenantId}/";
    public const string AadIssuer = $"https://login.microsoftonline.com/{TenantId}/v2.0";
}
