---
name: dotnet-di-services
description: 'Dependency injection and service registration best practices for .NET/C#.'
---

## Scope

Analyze `${selection}` if provided. If no selection is made, analyze ALL C# files (`**/*.cs`) in the workspace.

## Execution Rules

- Process **every file in scope**. Do not skip any.
- **DO NOT STOP** until all files have been reviewed.
- If context limits are reached, emit a **checkpoint summary** then await continuation.

## Dependency Injection & Services

- Use **constructor dependency injection** with `ArgumentNullException.ThrowIfNull` guards.
- Register services with appropriate lifetimes: `Singleton`, `Scoped`, or `Transient`.
- **Avoid captive dependencies**: a `Singleton` service must not depend on a `Scoped` or `Transient` service. The shorter-lived service is captured for the application’s lifetime, leading to stale state and concurrency bugs.
- Use `Microsoft.Extensions.DependencyInjection` patterns (`IServiceCollection` extension methods).
- Implement **service interfaces** for all services to support testability and mocking.
- For multiple implementations of the same interface, use **.NET 8+ Keyed Services** (`services.AddKeyedScoped<IFoo, Bar>("key")`) rather than factory delegates or ad-hoc named-service patterns.

### Example

```csharp
// Service interface
public interface IRiskService
{
    Task<IReadOnlyList<Risk>> GetAllAsync(CancellationToken cancellationToken);
}

// Registration (extension method)
public static class RiskServiceExtensions
{
    public static IServiceCollection AddRiskServices(this IServiceCollection services)
    {
        services.AddScoped<IRiskService, RiskService>();
        return services;
    }
}
```

## Findings Summary Format

| File | Severity | Section Violated | Description | Recommended Fix |
|------|----------|-----------------|-------------|-----------------|
| ...  | Warning  | Dependency Injection & Services | Service registered without interface | Extract interface and register via `AddScoped<IFoo, Foo>()` |
