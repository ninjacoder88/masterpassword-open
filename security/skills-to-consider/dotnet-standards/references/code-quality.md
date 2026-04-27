---
name: dotnet-code-quality
description: 'Code quality and SOLID principles best practices for .NET/C#.'
---

## Scope

Analyze `${selection}` if provided. If no selection is made, analyze ALL C# files (`**/*.cs`) in the workspace.

## Execution Rules

- Process **every file in scope**. Do not skip any.
- **DO NOT STOP** until all files have been reviewed.
- If context limits are reached, emit a **checkpoint summary** then await continuation.

## Code Quality

- Ensure **SOLID principles** compliance (Single Responsibility, Open/Closed, Liskov, Interface Segregation, Dependency Inversion).
- Avoid code duplication — extract shared logic to base classes or utility methods.
- **Remove unused `using` directives** and sort the remaining ones alphabetically.
- Follow consistent naming conventions:
  - `PascalCase` for types, methods, properties, and constants.
  - `camelCase` for parameters and local variables.
  - `_camelCase` for private fields.
- Use meaningful names that reflect **domain concepts** (e.g., `riskImpactScore` not `val`).
- Keep methods **focused and cohesive** — single responsibility per method.
- Implement `IDisposable` / `IAsyncDisposable` patterns for types holding unmanaged resources.
- Move all constants to a **separate `static` class** (e.g., `RiskDomainConstants`).
- Format code according to C# conventions: consistent spacing, braces on new lines, no trailing whitespace.
- Enable **nullable reference types** (`<Nullable>enable</Nullable>` in the project file). Annotate nullable parameters and return types with `?`; avoid the null-forgiving operator (`!`) except where unavoidable.
- Use **file-scoped namespaces** (`namespace Foo.Bar;`) in all new or touched files to reduce nesting (requires C# 10+).
- Prefer `var` when the type is immediately obvious from the right-hand side. Use explicit types when clarity is improved.
- Prefer **pattern matching** (`switch` expressions, `is` patterns, positional deconstruction) over long `if`/`else` chains or legacy `switch` statements.
- Use **collection expressions** (`[item1, item2]`) for array and collection initialisation where supported (requires C# 12+).
- Prefer **`IReadOnlyList<T>`** or **`IEnumerable<T>`** as public return types for collections to prevent unintended mutation by callers. Return `IList<T>` / `List<T>` only when the caller is explicitly expected to modify the collection.

### Constants Example

```csharp
// Before — inline magic strings/numbers
if (risk.Score > 8) { ... }

// After — extracted to constants class
public static class RiskDomainConstants
{
    public const int CriticalScoreThreshold = 8;
}

if (risk.Score > RiskDomainConstants.CriticalScoreThreshold) { ... }
```

### Modern C# / .NET Modernizations
Apply the following modernizations whenever the target **C# language version** and **.NET runtime/BCL** support them. For each bullet, respect the minimum detected `<LangVersion>` across projects and the lowest `<TargetFramework>`: use C# 14 / .NET 10-only features (such as the `field` keyword and `extension` members) only when those versions are targeted, but still apply guidance that is valid for earlier versions (for example, .NET 8 frozen collections or C# 13 `params ReadOnlySpan<T>` overloads) as soon as they are available.
- Use the **`field` keyword** (C# 14) inside auto-properties that need validation or lazy initialisation, eliminating the need for a manually declared backing field when targeting C# 14+.
- Use the new **`extension` member syntax** (C# 14) instead of separate static extension-method classes when adding purely additive behaviour to a type and the project targets C# 14+.
- Prefer **`Span<T>`** and **`ReadOnlySpan<T>`** over heap-allocated arrays or substrings for short-lived, stack-allocated slices on hot paths (e.g., string parsing, buffer manipulation) when those types are available (for example, .NET Standard 2.1+ / .NET Core 3.0+ / .NET 5+).
- Use **`ValueTask`** and **`ValueTask<T>`** for async methods that frequently return synchronously (cached results, in-memory reads). Default to `Task`/`Task<T>` for all other async methods (see `async-patterns.md`).
- Use **frozen collections** (`FrozenDictionary<TKey,TValue>`, `FrozenSet<T>`, available since .NET 8) for lookup tables that are populated once at startup and read many times — they offer lower memory overhead and faster lookups than `Dictionary` for read-only scenarios when targeting .NET 8+.
- Apply **`params ReadOnlySpan<T>`** (C# 13+) overloads on frequently-called helpers that accept a variable number of value-type arguments to avoid implicit array allocation when targeting C# 13+.

#### `field` Keyword Example

```csharp
// Before (C# ≤ 13) — manual backing field required
private string _name = string.Empty;
public string Name
{
    get => _name;
    set => _name = string.IsNullOrWhiteSpace(value)
        ? throw new ArgumentException("Name cannot be empty.", nameof(value))
        : value;
}

// After (C# 14) — `field` refers to the compiler-generated backing field
public string Name
{
    get;
    set => field = string.IsNullOrWhiteSpace(value)
        ? throw new ArgumentException("Name cannot be empty.", nameof(value))
        : value;
}
```

#### `Span<T>` Hot-Path Example

```csharp
// Before — allocates a new string on each call
public static string TrimPrefix(string input, string prefix)
    => input.StartsWith(prefix) ? input[prefix.Length..] : input;

// After — zero-allocation span slice
public static ReadOnlySpan<char> TrimPrefix(ReadOnlySpan<char> input, ReadOnlySpan<char> prefix)
    => input.StartsWith(prefix) ? input[prefix.Length..] : input;
```

#### `IReadOnlyList<T>` Return Type Example

```csharp
// Before — exposes internal list; caller can mutate it
public List<RiskItem> GetRisks() => _risks;

// After — cached read-only projection; internal state is protected
private readonly IReadOnlyList<RiskItem> _readOnlyRisks;
public RiskService(List<RiskItem> risks)
{
    // Single allocation; reuse for all calls; defensive copy protects internal state
    _readOnlyRisks = new List<RiskItem>(risks).AsReadOnly();
}
public IReadOnlyList<RiskItem> GetRisks() => _readOnlyRisks;
```

---

## Findings Summary Format

| File | Severity | Section Violated | Description | Recommended Fix |
|------|----------|-----------------|-------------|-----------------|
| ...  | Warning  | Code Quality | Magic number used inline | Extract to `RiskDomainConstants` static class |
