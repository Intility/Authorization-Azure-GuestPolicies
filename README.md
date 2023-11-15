# Intility.Authorization.Azure.GuestPolicies
Deny guests users in the authorization flow.

Install the _Intility.Authorization.Azure.GuestPolicies_ [NuGet package](https://www.nuget.org/packages/Intility.Authorization.Azure.GuestPolicies/)

```powershell
Install-Package Intility.Authorization.Azure.GuestPolicies
```

Then, add the policy to the `AuthorizationPolicyBuilder`:

```csharp
builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .DenyGuests()
        .Build();
});
```