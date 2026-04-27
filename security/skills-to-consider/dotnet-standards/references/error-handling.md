---
name: dotnet-error-handling
description: 'Error handling and structured logging best practices for .NET/C#.'
---

## Scope

Analyze `${selection}` if provided. If no selection is made, analyze ALL C# files (`**/*.cs`) in the workspace.

## Execution Rules

- Process **every file in scope**. Do not skip any.
- **DO NOT STOP** until all files have been reviewed.
- If context limits are reached, emit a **checkpoint summary** then await continuation.

## Error Handling & Logging

- Use **structured logging** with `Microsoft.Extensions.Logging` (`ILogger<T>`).
- Log method entries, exits, and key decision points with appropriate log levels (`LogDebug`, `LogInformation`, `LogWarning`, `LogError`).
- Use **message templates** (not string interpolation) to avoid unnecessary allocations: `_logger.LogInformation("Processing risk {RiskId}", id)`.
- For high-frequency logging, use the **`[LoggerMessage]` source generator** (available from .NET 6) to produce zero-allocation, compile-time-validated log methods.
- Throw **specific, descriptive exceptions** rather than `Exception` or `ApplicationException`.
- Use `try`/`catch` only for expected failure scenarios; let unexpected exceptions propagate to global middleware.
- Handle global exceptions in ASP.NET Core using **`IExceptionHandler`** (.NET 8+) registered via `services.AddExceptionHandler<T>()`, rather than custom middleware.
- Return **`ProblemDetails`** (RFC 7807) for API error responses. Use `TypedResults.Problem(...)` or the built-in `IProblemDetailsService` for consistent error payloads.
- Use `ILogger` scopes (`using (_logger.BeginScope(...))`) for correlated log context.
- Use `ArgumentException.ThrowIfNullOrEmpty` and `ArgumentOutOfRangeException.ThrowIfNegativeOrZero` for guard-clause input validation in public methods.

### Example

```csharp
// Before — console output, generic exception, string interpolation in log
Console.WriteLine("Error: " + ex.Message);
throw new Exception("Something went wrong");

// After — structured logging, specific exception
_logger.LogError(ex, "Failed to retrieve risk {RiskId}", id);
throw new RiskNotFoundException(id);

// Hot-path logging with zero allocations ([LoggerMessage] source generator)
public static partial class Log
{
    [LoggerMessage(Level = LogLevel.Error, Message = "Failed to retrieve risk {RiskId}")]
    public static partial void RiskRetrievalFailed(ILogger logger, Guid riskId, Exception ex);
}
```

## Findings Summary Format

| File | Severity | Section Violated | Description | Recommended Fix |
|------|----------|-----------------|-------------|-----------------|
| ...  | Warning  | Error Handling & Logging | String interpolation used in log call | Replace with structured message template |
