---
name: dotnet-configuration
description: 'Configuration and settings best practices for .NET/C#.'
---

## Scope

Analyze `${selection}` if provided. If no selection is made, analyze ALL C# files (`**/*.cs`) in the workspace.

## Execution Rules

- Process **every file in scope**. Do not skip any.
- **DO NOT STOP** until all files have been reviewed.
- If context limits are reached, emit a **checkpoint summary** then await continuation.

## Configuration & Settings

- Use **strongly-typed configuration classes** with data annotations.
- Apply validation attributes: `[Required]`, `[Range]`, `[MinLength]`, etc.
- Bind configuration via `IConfiguration.GetSection("Key").Get<TOptions>()` or `services.Configure<TOptions>()`.
- Support `appsettings.json` and `appsettings.{Environment}.json` overrides.
- Choose the correct `IOptions` variant based on service lifetime:
  - `IOptions<T>` — singleton, does **not** reload; use for app-startup configuration.
  - `IOptionsSnapshot<T>` — scoped, reloads per request; use in web APIs.
  - `IOptionsMonitor<T>` — singleton, fires change notifications; use for long-running background services.
- Options classes should be `sealed` to prevent inheritance from bypassing validation.
- Use the `required` keyword (C# 11+) on mandatory string/reference properties instead of relying solely on `[Required]`.

### Example

```csharp
// Strongly-typed options class
public sealed class DatabaseOptions
{
    [Required]
    public required string ConnectionString { get; init; }

    [Range(1, 300)]
    public int CommandTimeoutSeconds { get; init; } = 30;
}

// Registration in Program.cs
builder.Services
    .AddOptions<DatabaseOptions>()
    .BindConfiguration("Database")
    .ValidateDataAnnotations()
    .ValidateOnStart();
```

## Findings Summary Format

| File | Severity | Section Violated | Description | Recommended Fix |
|------|----------|-----------------|-------------|-----------------|
| ...  | Warning  | Configuration & Settings | Raw `IConfiguration["Key"]` string access | Replace with strongly-typed options class bound via `Configure<T>()` |
