---
name: dotnet-localization
description: 'User-facing string localization using IStringLocalizer for .NET/C# code.'
---

## Scope

Analyze `${selection}` if provided. If no selection is made, analyze ALL C# files (`**/*.cs`) in the workspace.

## Execution Rules

- Process **every file in scope**. Do not skip any.
- **DO NOT STOP** until all files have been reviewed.
- If context limits are reached, emit a **checkpoint summary** then await continuation.

## Resource Management & Localization

> **Critical distinction:** Structured log message templates must **not** be externalised to resource files. Log analysis tools (Application Insights, ELK, Seq) rely on consistent, static template strings for log correlation and aggregation — externalising them breaks this. Only **user-facing strings** (UI labels, validation messages, exception messages shown to end users) should be localized.

### Rules

- Move hard-coded **user-facing strings** (error messages shown to users, UI labels, validation text) to `.resx` resource files. Create the files if they do not exist.
- **Do not move structured log templates** (`LogInformation`, `LogError`, etc.) to `.resx` files — these must remain as static string literals in source code.
- Use **`IStringLocalizer<T>`** from `Microsoft.Extensions.Localization` to access localized strings at runtime. This integrates with the DI container and respects the request culture automatically. Do not use the legacy `ResourceManager` API directly.
- Maintain one resource file per feature for user-facing strings:
  - `ErrorMessages.resx` — exception and validation messages shown to users

### Resource File Structure

```
Shared/
  Resources/
    ErrorMessages.resx
```

### Registration

```csharp
// Program.cs
builder.Services.AddLocalization(options => options.ResourcesPath = "Resources");
```

### Example

```csharp
// Before
throw new InvalidOperationException("Risk not found.");
_logger.LogInformation("Fetching risk with id {Id}.", id);   // ← do NOT localize this

// After — inject IStringLocalizer<RiskService> via constructor
throw new InvalidOperationException(_localizer["RiskNotFound"]);
_logger.LogInformation("Fetching risk with id {Id}.", id);   // ← keep as static template
```

## Findings Summary Format

| File | Severity | Section Violated | Description | Recommended Fix |
|------|----------|-----------------|-------------|-----------------|
| ...  | Info     | Resource Management & Localization | Hard-coded user-facing error string in exception | Move to `ErrorMessages.resx` and access via `IStringLocalizer<T>` |
