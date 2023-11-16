# Intility.Authorization.Azure.GuestPolicies
Deny guests users in the authorization flow.

[![Build_and_Test](https://github.com/Intility/Authorization-Azure-GuestPolicies/actions/workflows/Build_and_Test.yml/badge.svg)](https://github.com/Intility/Authorization-Azure-GuestPolicies/actions/workflows/Build_and_Test.yml)
[![Publish](https://github.com/Intility/Authorization-Azure-GuestPolicies/actions/workflows/Publish.yml/badge.svg)](https://github.com/Intility/Authorization-Azure-GuestPolicies/actions/workflows/Publish.yml)
[![codecov](https://codecov.io/gh/Intility/Authorization-Azure-GuestPolicies/graph/badge.svg?token=CBkggqQ7ge)](https://codecov.io/gh/Intility/Authorization-Azure-GuestPolicies)

![Nuget](https://img.shields.io/nuget/v/Intility.Authorization.Azure.GuestPolicies?label=Intility.Authorization.Azure.GuestPolicies)
![Nuget](https://img.shields.io/nuget/dt/Intility.Authorization.Azure.GuestPolicies?logo=nuget&label=Downloads)

Install the _Intility.Authorization.Azure.GuestPolicies_ [NuGet package](https://www.nuget.org/packages/Intility.Authorization.Azure.GuestPolicies/)

```powershell
Install-Package Intility.Authorization.Azure.GuestPolicies
```

Then, add the policy to the `AuthorizationPolicyBuilder`:

```csharp

builder.Services.AddDenyGuestsAuthorization();

builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .DenyGuests()
        .Build();
});
```