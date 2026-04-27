---
name: dotnet-async-patterns
description: 'Async/await best practices for .NET/C# code.'
---

## Scope

Analyze `${selection}` if provided. If no selection is made, analyze ALL C# files (`**/*.cs`) in the workspace.

## Execution Rules

- Process **every file in scope**. Do not skip any.
- **DO NOT STOP** until all files have been reviewed.
- If context limits are reached, emit a **checkpoint summary** then await continuation.

## Async/Await Patterns

- Use `async`/`await` for all I/O operations and long-running tasks.
- Return `Task` or `Task<T>` from async methods. Never return `void` from async methods (except event handlers).
- Use `ConfigureAwait(false)` in **library and infrastructure code** to avoid deadlocks. In ASP.NET Core application-layer code, no `SynchronizationContext` is present so deadlocks cannot occur — `ConfigureAwait(false)` there is a style choice, not a correctness requirement.
- Always pass and respect `CancellationToken` in async method signatures. By convention the `CancellationToken` must be the **last parameter**.
- Handle async exceptions with `try`/`catch` rather than `.Result` or `.Wait()`.
- Use `IAsyncEnumerable<T>` with `await foreach` for streaming or large data sets to avoid buffering the entire result in memory.
- Use `ValueTask<T>` instead of `Task<T>` for hot-path methods that frequently complete synchronously (e.g., cached reads), to reduce heap allocations.

### Example

```csharp
// Before
public Risk GetById(Guid id)
{
    return _repository.GetByIdAsync(id).Result; // deadlock risk
}

// After
public async Task<Risk?> GetByIdAsync(Guid id, CancellationToken cancellationToken)
{
    return await _repository.GetByIdAsync(id, cancellationToken).ConfigureAwait(false);
}
```

## Findings Summary Format

| File | Severity | Section Violated | Description | Recommended Fix |
|------|----------|-----------------|-------------|-----------------|
| ...  | Critical | Async/Await Patterns | Synchronous blocking call `.Result` used | Convert to `await` with `ConfigureAwait(false)` |
