from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend
from langchain_aws import ChatBedrockConverse
from langchain_core.tools import tool
from dotenv import load_dotenv
from datetime import datetime
import json
import os
import requests
import git
import boto3
from botocore.config import Config


load_dotenv(overrides=True)

# Git repo setup
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
repo_url = "https://github.com/redpointsec/vtm.git"
repo_path = os.path.join(SCRIPT_DIR, "repo")

if os.path.isdir(repo_path) and os.path.isdir(os.path.join(repo_path, ".git")):
    print("Directory already contains a git repository.")
else:
    try:
        repo = git.Repo.clone_from(repo_url, repo_path)
        print(f"Repository cloned into: {repo_path}")
    except Exception as e:
        print(f"An error occurred while cloning the repository: {e}")

# LLM setup - lower temperature reduces hallucinated findings in code analysis
# Increased read_timeout (default 60s) because Phase 1 builds large context before each LLM call
_bedrock_config = Config(
    read_timeout=300,  # 5 minutes
    retries={"max_attempts": 2, "mode": "adaptive"},
)
llm = ChatBedrockConverse(
    model_id="qwen.qwen3-coder-30b-a3b-v1:0",
    temperature=0.2,
    client=boto3.client("bedrock-runtime", config=_bedrock_config),
)

# Backend for local filesystem access - points to the repo directory
# virtual_mode=True restricts access to root_dir only (recommended for security)
filesystem_backend = FilesystemBackend(root_dir=repo_path, virtual_mode=True)

# Output directory: <workspace_root>/security_findings/
WORKSPACE_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
FINDINGS_DIR = os.path.join(WORKSPACE_ROOT, "security_findings")

print(f"Repo path: {repo_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Custom tool: CVE / SCA lookup via OSV.dev
# This tool is NOT sandboxed by FilesystemBackend — it runs as regular Python
# and makes outbound HTTPS calls to api.osv.dev.
# ─────────────────────────────────────────────────────────────────────────────
@tool
def cve_lookup(requirements_path: str) -> str:
    """
    Read a requirements.txt file, then query the OSV.dev API for known CVEs
    (or any vulnerability) for each listed Python package.
    Returns a JSON string summarising all vulnerabilities found.
    Pass the full path to the requirements.txt file on disk.
    """
    try:
        with open(requirements_path) as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        return json.dumps({"error": f"File not found: {requirements_path}"})

    results = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Parse "package==version", "package>=version", or bare "package"
        for sep in ("==", ">=", "<=", "~=", "!="):
            if sep in line:
                name, version = line.split(sep, 1)
                version = version.split(",")[0].strip()  # take first constraint
                break
        else:
            name, version = line, None

        name = name.strip()
        payload: dict = {"package": {"name": name, "ecosystem": "PyPI"}}
        if version:
            payload["version"] = version

        try:
            resp = requests.post(
                "https://api.osv.dev/v1/query",
                json=payload,
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            results.append({"package": name, "version": version, "error": str(exc)})
            continue

        vulns = data.get("vulns", [])
        for v in vulns:
            results.append(
                {
                    "package": name,
                    "version": version,
                    "id": v.get("id"),
                    "summary": v.get("summary", ""),
                    "severity": (
                        v.get("database_specific", {}).get("severity")
                        or (
                            v.get("severity", [{}])[0].get("score")
                            if v.get("severity")
                            else "UNKNOWN"
                        )
                    ),
                    "references": [r.get("url") for r in v.get("references", [])[:3]],
                }
            )

    if not results:
        return json.dumps({"message": "No known CVEs found for listed packages."})
    return json.dumps(results, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Phase system prompts
# ─────────────────────────────────────────────────────────────────────────────

RECON_PROMPT = """You are a code reconnaissance agent performing the first step of a SAST pipeline.

Your ONLY job is to map the application and collect raw material — do NOT label anything as vulnerable yet.

### Permitted tools — you may ONLY call these four, nothing else
- `ls` — list a directory
- `glob` — find files by pattern
- `read_file` — read a file (NO offset/limit pagination; read each file once in full)
- `cve_lookup` — check CVEs (call exactly once)

### FORBIDDEN — calling any of these ends the task in failure
- `grep` — do NOT call grep under any circumstances
- `write_file`, `edit_file` — do NOT write anything
- Paginated `read_file` (with offset= or limit=) — do NOT paginate

### Exploration rules
- All paths are ABSOLUTE virtual paths starting with `/`. The Django app lives at `/taskManager/`.
- `ls(path='/taskManager')` ONCE only. Do NOT ls any subdirectory or the repo root.
- `glob(pattern='**/*.py', path='/taskManager')` ONCE only. Do NOT glob from `/`.
- Do NOT enter or list: `static/`, `media/`, `uploads/`, `templates/`, `migrations/`, `fixtures/`, `tests/`, `__pycache__/`, `.git/`, `node_modules/`, `htmlcov/`, `assets/`.

### Required steps — execute in this exact order, then STOP
1. `ls(path='/taskManager')` — once.
2. `glob(pattern='**/*.py', path='/taskManager')` — once.
3. `read_file` (no offset, no limit) on each file below that exists — skip missing ones:
   - `/taskManager/settings.py`
   - `/taskManager/urls.py` and any `*_urls.py` under `/taskManager/`
   - `/taskManager/views.py`
   - `/taskManager/models.py`
   - `/taskManager/forms.py`
   - `/taskManager/middleware.py`
   - `/taskManager/serializers.py`
   - `/taskManager/misc.py`
4. `cve_lookup` — once, with the full path to `requirements.txt`.
5. **Immediately emit the JSON below. Do NOT call any tool after cve_lookup — not grep, not ls, not read_file. Your very next output must be the JSON.**

### Output Format
Respond ONLY with a JSON object — no prose:

```json
{
  "app_structure": ["list of key file paths discovered"],
  "django_settings": {
    "DEBUG": "<value>",
    "ALLOWED_HOSTS": "<value>",
    "SECRET_KEY": "<value or 'not found'>",
    "MIDDLEWARE": ["list"],
    "AUTH_PASSWORD_VALIDATORS": ["list"],
    "SESSION_COOKIE_SECURE": "<value or 'not set'>",
    "CSRF_COOKIE_SECURE": "<value or 'not set'>"
  },
  "endpoints": [
    {"url_pattern": "<pattern>", "view": "<view name>", "requires_auth": true}
  ],
  "code_snippets": {
    "<relative/path.py>": "<full file content or key excerpt>"
  },
  "sca_findings": <raw output from cve_lookup tool, as a JSON array>
}
```
"""

ANALYSIS_PROMPT = """You are a vulnerability analyst performing the second step of a SAST pipeline.

You will receive a JSON code map produced by the recon agent. Analyse the code snippets and settings
to identify ALL potential security vulnerabilities. Be thorough — err on the side of including more
candidates here; they will be validated in the next step.

Do NOT use the filesystem tools. Work only from the provided code map.

### Vulnerability classes to check
- **A01 Broken Access Control**: Missing `@login_required`, IDOR, horizontal privilege escalation
- **A02 Cryptographic Failures**: Hardcoded secrets, weak hashing (MD5/SHA1 for passwords), plaintext storage
- **A03 Injection**: `raw()`, `extra()`, `RawSQL()`, `cursor.execute()` with unsanitised input; `shell=True`; `eval`/`exec`
- **A05 Security Misconfiguration**: `DEBUG=True`, `ALLOWED_HOSTS=['*']`, missing security middleware
- **A07 Auth Failures**: Weak passwords, missing brute-force protection, insecure sessions
- **A08 Data Integrity**: Mass assignment via `**request.POST`, unsafe deserialization
- **Django-specific**: `@csrf_exempt`, `mark_safe()` on user input, `safe` template filter
- **SCA / A06 Vulnerable Components**: Pull in any issues from `sca_findings` in the code map

### Output Format
Respond ONLY with a JSON array of candidate findings — no prose:

```json
[
  {
    "file": "<relative path>",
    "line": <estimated line number or null>,
    "pattern": "<the exact code or setting that triggered this>",
    "vulnerability_class": "A0X - <Name>",
    "description": "<what is wrong and why it matters>",
    "source": "sast | sca"
  }
]
```
"""

REPORT_PROMPT = """You are a senior application security engineer performing the final triage step of a SAST pipeline.

You will receive a JSON array of candidate findings from the analysis agent. Your job is to:
1. Remove false positives (e.g. findings neutralised by downstream sanitisation).
2. Assign accurate severity: Critical / High / Medium / Low.
3. Write a concrete attack scenario for each confirmed finding.
4. Write a specific remediation (code change, Django setting, or library).

You MAY use the filesystem tools to verify a finding if you are unsure.

### Output Format
Respond ONLY with the final JSON report — no prose:

```json
{
  "summary": {
    "total_findings": <int>,
    "critical": <int>,
    "high": <int>,
    "medium": <int>,
    "low": <int>
  },
  "findings": [
    {
      "id": "FINDING-001",
      "title": "<short descriptive title>",
      "severity": "Critical | High | Medium | Low",
      "owasp_category": "A0X - <Category Name>",
      "cwe": "CWE-<number>",
      "file": "<relative file path>",
      "line": <line number or null>,
      "description": "<1-2 sentences>",
      "evidence": "<exact code snippet or setting value>",
      "attack_scenario": "<concrete attacker action and impact>",
      "remediation": "<specific fix>"
    }
  ]
}
```
"""

# ─────────────────────────────────────────────────────────────────────────────
# Report persistence
# ─────────────────────────────────────────────────────────────────────────────

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sev_badge(sev: str) -> str:
    return {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
    }.get(sev.lower(), sev.upper())


def save_report(parsed: dict, run_ts: datetime) -> tuple[str, str]:
    """
    Write <FINDINGS_DIR>/sast_<timestamp>.md and .json.
    Returns (md_path, json_path).
    """
    os.makedirs(FINDINGS_DIR, exist_ok=True)
    slug = run_ts.strftime("%Y-%m-%d_%H-%M-%S")
    md_path = os.path.join(FINDINGS_DIR, f"sast_{slug}.md")
    json_path = os.path.join(FINDINGS_DIR, f"sast_{slug}.json")

    summary = parsed.get("summary", {})
    findings = parsed.get("findings", [])

    # ── Markdown ──────────────────────────────────────────────────────────────
    lines = [
        "# SAST Security Report",
        "",
        f"**Run:** {run_ts.strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Target:** VTM (Django — `taskManager/`)  ",
        f"**Model:** qwen.qwen3-coder-30b-a3b-v1:0",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
        f"| Critical | {summary.get('critical', 0)} |",
        f"| High     | {summary.get('high', 0)} |",
        f"| Medium   | {summary.get('medium', 0)} |",
        f"| Low      | {summary.get('low', 0)} |",
        f"| **Total** | **{summary.get('total_findings', len(findings))}** |",
        "",
        "---",
        "",
        "## Findings",
        "",
    ]

    for f in findings:
        sev = f.get("severity", "Unknown")
        lines += [
            f"### {f.get('id')} · {_sev_badge(sev)} — {f.get('title')}",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| File | `{f.get('file')}` line {f.get('line')} |",
            f"| OWASP | {f.get('owasp_category')} |",
            f"| CWE | {f.get('cwe')} |",
            "",
            "**Evidence:**",
            "",
            f"```",
            f"{f.get('evidence', '').strip()}",
            f"```",
            "",
            f"**Description:** {f.get('description', '')}",
            "",
            f"**Attack Scenario:** {f.get('attack_scenario', '')}",
            "",
            f"**Remediation:** {f.get('remediation', '')}",
            "",
            "---",
            "",
        ]

    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    # ── JSON ──────────────────────────────────────────────────────────────────
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(parsed, fh, indent=2)

    return md_path, json_path


# ─────────────────────────────────────────────────────────────────────────────
# Phase helpers
# ─────────────────────────────────────────────────────────────────────────────


def create_phase_agent(
    system_prompt: str,
    extra_tools: list = None,
    backend=filesystem_backend,
):
    """Create a fresh DeepAgent for a single analysis phase."""
    return create_deep_agent(
        model=llm,
        tools=extra_tools or [],
        backend=backend,
        system_prompt=system_prompt,
    )


def run_phase(
    phase_name: str,
    system_prompt: str,
    task: str,
    extra_tools: list = None,
    backend=filesystem_backend,
) -> str:
    """
    Run a single analysis phase: create a phase-specific agent, stream its
    output, and return the final text response.
    """
    print(f"\n[{phase_name}] Starting...")
    agent = create_phase_agent(system_prompt, extra_tools, backend=backend)
    final_output = ""
    for event in agent.stream({"messages": [{"role": "user", "content": task}]}):
        for key, value in event.items():
            if "Middleware" in key:
                continue
            if isinstance(value, dict) and "messages" in value:
                for msg in value["messages"]:
                    if hasattr(msg, "tool_calls") and msg.tool_calls:
                        for tc in msg.tool_calls:
                            args_preview = ", ".join(
                                f"{k}={repr(v)[:60]}"
                                for k, v in tc.get("args", {}).items()
                            )
                            print(f"  -> {tc['name']}({args_preview})")
                    elif hasattr(msg, "content") and msg.content:
                        final_output = msg.content
    print(f"[{phase_name}] Done.")
    return final_output


if __name__ == "__main__":
    run_ts = datetime.now()
    print("DeepAgent SAST Demo — Multi-Phase Pipeline")
    print("=" * 60)

    # ── Phase 1: Reconnaissance ───────────────────────────────────────────────
    recon_task = (
        "Collect the Django app source using ONLY these tools in order: "
        "ls, glob, read_file (no pagination), cve_lookup. "
        "Do NOT call grep, write_file, edit_file, or any other tool. "
        "App is at `/taskManager/`. "
        "Use `glob(pattern='**/*.py', path='/taskManager')` — do NOT glob from `/`. "
        f"Call `cve_lookup` exactly once with the path '{repo_path}/requirements.txt'. "
        "After cve_lookup finishes, your next output MUST be the JSON code map — "
        "do not call any more tools."
    )
    recon_result = run_phase(
        "Phase 1 — Recon",
        RECON_PROMPT,
        recon_task,
        extra_tools=[cve_lookup],
    )

    # ── Phase 2: Vulnerability Analysis ──────────────────────────────────────
    analysis_task = (
        "Below is the code map produced by the reconnaissance agent.\n"
        "Analyse it and identify all candidate vulnerabilities.\n"
        "Return only the JSON candidate findings array described in your instructions.\n\n"
        "--- CODE MAP ---\n" + recon_result
    )
    analysis_result = run_phase(
        "Phase 2 — Analysis",
        ANALYSIS_PROMPT,
        analysis_task,
        backend=None,  # No filesystem access — analysis works purely from the code map text
    )

    # ── Phase 3: Triage & Report ──────────────────────────────────────────────
    report_task = (
        "Below is the list of candidate findings produced by the analysis agent.\n"
        "Triage them and produce the final security report.\n"
        "Return only the JSON report described in your instructions.\n\n"
        "--- CANDIDATE FINDINGS ---\n" + analysis_result
    )
    report_result = run_phase(
        "Phase 3 — Report",
        REPORT_PROMPT,
        report_task,
    )

    # ── Print final report ────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("FINAL SECURITY REPORT:")

    raw = report_result.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
    try:
        parsed = json.loads(raw)
        summary = parsed.get("summary", {})
        print(
            f"\nSummary: {summary.get('total_findings', '?')} findings "
            f"| Critical: {summary.get('critical', 0)} "
            f"| High: {summary.get('high', 0)} "
            f"| Medium: {summary.get('medium', 0)} "
            f"| Low: {summary.get('low', 0)}"
        )
        print()
        for finding in parsed.get("findings", []):
            sev = finding.get("severity", "").upper()
            print(f"[{sev}] {finding.get('id')} — {finding.get('title')}")
            print(f"  File     : {finding.get('file')} (line {finding.get('line')})")
            print(
                f"  OWASP    : {finding.get('owasp_category')}  |  CWE: {finding.get('cwe')}"
            )
            print(f"  Evidence : {finding.get('evidence', '').strip()}")
            print(f"  Impact   : {finding.get('attack_scenario', '')}")
            print(f"  Fix      : {finding.get('remediation', '')}")
            print()
        print("--- Raw JSON ---")
        print(json.dumps(parsed, indent=2))

        # ── Persist to disk ───────────────────────────────────────────────────
        md_path, json_path = save_report(parsed, run_ts)
        print(f"\nReport saved:")
        print(f"  Markdown : {md_path}")
        print(f"  JSON     : {json_path}")
    except (json.JSONDecodeError, ValueError):
        print(report_result)
        print("\n[WARNING] Could not parse report JSON — skipping file save.")
