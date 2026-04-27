---
name: dotnet-standards
description: >-
  Reviews and refactors .NET/C# code: fixes async patterns, validates DI registration, corrects error handling, adds documentation, enforces style conventions.
  USE FOR: review C# code, audit project, enforce coding standards, apply .NET best practices, clean up code, fix style issues,
  apply coding standards, tidy up this file, make this idiomatic C#, fix code quality issues, get PR-ready, prepare for code review,
  add documentation, fix async patterns, check DI registration, check error handling, fix configuration,
  bring this up to standard, make this code production-ready.
  DO NOT USE FOR: non-.NET codebases, read-only .NET questions, trivial single-variable edits.
---

## Use When

- Review, audit, or enforce .NET/C# coding standards
- Fix or clean up code quality issues in one or more C# files
- Apply best practices, prepare for PR/code review, or onboard a codebase
- Target a sub-skill area: documentation, architecture, DI, localization, async patterns, configuration, error handling, or code quality

> See [references/trigger-phrases.md](references/trigger-phrases.md) for example trigger phrases per category.

## Do Not Invoke For

- Non-C# / non-.NET codebases
- Read-only .NET questions — answer directly without running the full skill
- Trivial edits unrelated to standards (e.g. rename a variable, add a property)

## Pre-Flight: Detect Target Framework

Before processing any files, inspect every `*.csproj` in the workspace:

- Read `<LangVersion>` and `<TargetFramework>` / `<TargetFrameworks>`.
- Record the minimum C# language version across all projects.
- Sub-skills that reference **C# 10+** features (file-scoped namespaces), **C# 11+** features (`required` keyword), **C# 12+** features (collection expressions, primary constructors), **C# 13+** features (`params ReadOnlySpan<T>`), or **C# 14+** features (`field` keyword, `extension` member syntax) must only be applied when the detected language version supports them.
- Determine the set of target frameworks (e.g., `net6.0`, `net7.0`, `net8.0`, `net8.0-*`) across all projects, and identify the lowest target framework.
- Only apply **.NET runtime–specific** recommendations when the target frameworks support them:
  - Treat `net8.0` and `net8.0-*` as supporting .NET 8 APIs (e.g., `IExceptionHandler`, Keyed DI services, `IProblemDetailsService`).
  - When all projects target **only `net6.0` / `net7.0`**, do **not** recommend APIs that were introduced in .NET 8 or later; instead, prefer equivalent patterns compatible with those target frameworks.
  - For multi-targeted projects, default to guidance that is compatible with the **lowest** target framework unless the user explicitly requests advice for a newer target.

## Scope

Analyze `${selection}` if provided. If no selection is made, analyze ALL C# files (`**/*.cs`) in the workspace, **excluding the files listed below**.

## Excluded Files

Skip files matching these patterns — applying fixes to generated or migrated code causes build failures:

- `**/*.g.cs`, `**/*.Designer.cs` — auto-generated source
- `**/obj/**`, `**/bin/**` — build output
- `**/Migrations/**` — EF Core migration files

**Test projects** (files under a project whose name contains `Tests`, `Specs`, or `Test`):
- Skip sub-skills **4 (Localization)** — these produce noise in test code.
- Apply all remaining sub-skills normally.

## Execution Rules

- **Before applying each sub-skill**, use the file reading tool to load the sub-skill file listed in the table below. Do not rely on memorised rules.
- Process **every file in scope**. Do not skip any.
- Execute **each sub-skill below in order**, sequentially, for every file.
- After completing all sub-skills, output a **consolidated findings summary table** grouped by file and sub-skill.
- For each finding, **write the corrected code directly to the file** using the file editing tools. Use `// ...existing code...` to preserve unchanged sections.
- **APPLY ALL CHANGES after the summary table** — do not stop at summarising. Every finding must result in an implemented edit.
- **DO NOT STOP** until every sub-skill has been applied to every file in scope and every finding has been fixed.
- If context limits are reached, emit a **checkpoint summary** listing:
  - Sub-skills completed
  - Files fully reviewed
  - Remaining files and sub-skills
  Then await the next prompt to continue from where you left off.

## Sub-Skills (execute in order)

| # | Sub-Skill | File | Focus Area |
|---|-----------|------|------------|
| 1 | Documentation | [references/documentation.md](references/documentation.md) | XML docs, inheritdoc, namespace structure |
| 2 | Architecture | [references/architecture.md](references/architecture.md) | Design patterns, records, primary constructors |
| 3 | DI & Services | [references/di-services.md](references/di-services.md) | DI registration, service interfaces, null guards, captive dependencies |
| 4 | Localization | [references/localization.md](references/localization.md) | User-facing strings, IStringLocalizer, .resx files |
| 5 | Async Patterns | [references/async-patterns.md](references/async-patterns.md) | async/await, ConfigureAwait, CancellationToken, ValueTask |
| 6 | Configuration | [references/configuration.md](references/configuration.md) | Strongly-typed options, IOptions variants, data annotations |
| 7 | Error Handling | [references/error-handling.md](references/error-handling.md) | Structured logging, LoggerMessage, specific exceptions, ProblemDetails |
| 8 | Code Quality | [references/code-quality.md](references/code-quality.md) | SOLID, nullable annotations, naming, constants, usings, disposal |

## Consolidated Findings Summary Format

After all sub-skills are complete, produce a single Markdown table:

| File | Sub-Skill | Severity | Description | Recommended Fix |
|------|-----------|----------|-------------|-----------------|
| ...  | ...       | Critical / Warning / Info | ...         | ...             |

**Severity:** Critical = correctness/runtime risk · Warning = maintainability/perf · Info = style

## Apply Findings

After outputting the summary table, apply findings in order:

1. Open the identified file.
2. Write the corrected code directly to the file.
3. Preserve all unchanged code using `// ...existing code...`.
4. Confirm each applied fix with a `✅` checklist item.
5. **Critical, Warning and Info** findings must all be fixed.
6. Do not stop until all **Critical, Warning and Info** findings are written to disk.