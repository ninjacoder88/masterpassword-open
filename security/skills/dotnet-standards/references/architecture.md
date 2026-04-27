---
name: dotnet-architecture
description: 'Design patterns and architecture best practices for .NET/C# code.'
---

## Scope

Analyze `${selection}` if provided. If no selection is made, analyze ALL C# files (`**/*.cs`) in the workspace.

## Execution Rules

- Process **every file in scope**. Do not skip any.
- **DO NOT STOP** until all files have been reviewed.
- If context limits are reached, emit a **checkpoint summary** then await continuation.

## Design Patterns & Architecture

- Use **primary constructor syntax** for dependency injection.
- Implement the **Command/Handler pattern** (or mediator pattern) to separate command intent from implementation. Generic base classes (e.g., `CommandHandler<TOptions>`) are one approach; align with whatever handler pattern is already established in the codebase.
- Use **interface segregation** with clear naming conventions (prefix interfaces with `I`).
- For projects that use a feature-folder or service-layer convention, place implementations in a separate `Impl/` subfolder. This is a **recommended convention, not a hard requirement**. Do not move files if the project already has an established folder structure (Clean Architecture, vertical slices, etc.).
- Follow the **Factory pattern** for complex object creation.
- Prefer **`record`** types for immutable value objects and DTOs. Use `record struct` for small, allocation-sensitive value types.

### Records vs. Classes

```csharp
// Prefer record for immutable DTOs
public record RiskSummary(Guid Id, string Title, int Score);

// Use class for mutable state or rich behaviour
public class RiskService(IRiskRepository repository) { ... }
```

### Primary Constructor Example

```csharp
// Before
public class RiskService
{
    private readonly IRiskRepository _repository;
    public RiskService(IRiskRepository repository) => _repository = repository;
}

// After
public class RiskService(IRiskRepository repository)
{
    public async Task<Risk?> GetByIdAsync(Guid id, CancellationToken ct)
        => await repository.GetByIdAsync(id, ct).ConfigureAwait(false);
}
```

## Findings Summary Format

| File | Severity | Section Violated | Description | Recommended Fix |
|------|----------|-----------------|-------------|-----------------|
| ...  | Info     | Design Patterns & Architecture | Implementation class not in `Impl/` folder | Consider moving to `Impl/` subfolder if project uses that convention |
