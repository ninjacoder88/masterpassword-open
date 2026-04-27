"""
DeepAgent SAST pipeline — language-agnostic edition.

Originally written for a Django/Python target, this version supports any
codebase (.NET / C#, Java, JavaScript/TypeScript, Go, Python, …) by:

1. Auto-detecting language + project layout (or accepting overrides via env vars
   / function args).
2. Driving Phase 1 (recon) with a prompt that is built dynamically from a
   `RepoConfig` instead of hard-coded Django paths.
3. Splitting Phase 2 (analysis) across multiple concurrent LLM calls so a large
   code map no longer blocks on a single multi-minute request.
4. Writing all findings under the `security/` folder (this script's directory).

Configuration knobs (all optional — sensible defaults are auto-detected):
    REPO_URL              Git URL to clone (skipped if REPO_PATH or repo/ exist)
    REPO_PATH             Local repo path (overrides clone target). May be the
                          workspace root itself if you want to scan the current
                          project.
    APP_ROOT              Subdirectory inside the repo to focus the scan on
                          (default: auto-detect, falls back to "/").
    LANGUAGE              Force a specific language profile
                          (csharp|python|java|javascript|go).
    ANALYSIS_WORKERS      Number of concurrent Phase-2 LLM calls (default 8).
    ANALYSIS_CHUNK_FILES  Number of source files per Phase-2 chunk (default 3).
                          Smaller chunks finish faster and are more parallelisable;
                          avoid values > 6 or Bedrock latency dominates.
    BEDROCK_MODEL_ID      Bedrock model ID. Default
                          ``qwen.qwen3-coder-30b-a3b-v1:0`` (matches the
                          original demo). For accounts/regions that require a
                          cross-region inference profile, pass the fully
                          prefixed ID instead, e.g.
                          ``us.qwen.qwen3-coder-30b-a3b-v1:0``.
    BEDROCK_REGION        Optional. Override the AWS region used for the
                          Bedrock client. By default boto3 picks it up from
                          ``AWS_REGION`` / ``AWS_DEFAULT_REGION`` /
                          ``~/.aws/config`` like every other AWS SDK call.
"""

from __future__ import annotations

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

import boto3
import git
import requests
from botocore.config import Config
from botocore.exceptions import ClientError
from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend
from dotenv import load_dotenv
from langchain_aws import ChatBedrockConverse
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool


load_dotenv(override=True)

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  # …/security
WORKSPACE_ROOT = os.path.dirname(SCRIPT_DIR)
FINDINGS_DIR = os.path.join(SCRIPT_DIR, "findings")  # security/findings/

# ------------------------------------------------------------------------------
# Skills Setup
# ------------------------------------------------------------------------------
# Skills are directories containing SKILL.md files with frontmatter metadata
# and instructions. DeepAgent loads these and injects them into the agent's
# context when relevant.
skills_dir = os.path.join(SCRIPT_DIR, "skills")

print(f"Skills directory: {skills_dir}")
print("Skills loaded:")
for skill_name in os.listdir(skills_dir):
    skill_path = os.path.join(skills_dir, skill_name, "SKILL.md")
    if os.path.exists(skill_path):
        print(f"  - {skill_name}")

# ─────────────────────────────────────────────────────────────────────────────
# LLM
# ─────────────────────────────────────────────────────────────────────────────
_bedrock_config = Config(
    read_timeout=300,
    retries={"max_attempts": 2, "mode": "adaptive"},
)

# Bedrock model. The default matches the original demo and is known to work
# against the user's account/region. Override with BEDROCK_MODEL_ID if needed
# (e.g. ``us.qwen.qwen3-coder-30b-a3b-v1:0`` for accounts that require the
# cross-region inference-profile prefix).
_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "qwen.qwen3-coder-30b-a3b-v1:0")

# Let boto3 pick the region from the user's standard AWS config chain
# (AWS_REGION / AWS_DEFAULT_REGION / ~/.aws/config). Override only if explicitly
# requested via BEDROCK_REGION.
_bedrock_client_kwargs = {"config": _bedrock_config}
if os.environ.get("BEDROCK_REGION"):
    _bedrock_client_kwargs["region_name"] = os.environ["BEDROCK_REGION"]

llm = ChatBedrockConverse(
    model_id=_MODEL_ID,
    temperature=0.2,
    client=boto3.client("bedrock-runtime", **_bedrock_client_kwargs),
)


# ─────────────────────────────────────────────────────────────────────────────
# Language profiles
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class LanguageProfile:
    name: str
    extensions: tuple[str, ...]
    manifest_files: tuple[str, ...]  # for SCA
    osv_ecosystem: str | None  # ecosystem name in OSV.dev
    project_markers: tuple[str, ...]  # files that mark an app root
    high_value_filename_patterns: tuple[
        str, ...
    ]  # regex for prioritised reads (legacy)
    handler_file_patterns: tuple[str, ...]  # regex for request-handler source files
    handler_class_markers: tuple[
        str, ...
    ]  # content regex that confirms a handler class
    auth_file_patterns: tuple[str, ...]  # regex for auth/config/crypto files
    ignore_dirs: tuple[str, ...]
    vulnerability_hints: str  # appended into Phase-2 prompt


_COMMON_IGNORES = (
    ".git",
    "node_modules",
    "bin",
    "obj",
    "dist",
    "build",
    "out",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    ".idea",
    ".vscode",
    "vendor",
    "Pods",
    "static",
    "assets",
    "media",
    "uploads",
    "fixtures",
    "htmlcov",
    "coverage",
    "tests",
    "test",
    "__tests__",
    "docs",
)

LANGUAGE_PROFILES: dict[str, LanguageProfile] = {
    "csharp": LanguageProfile(
        name="csharp",
        extensions=(".cs", ".cshtml", ".razor", ".config", ".json"),
        manifest_files=("*.csproj", "packages.config"),
        osv_ecosystem="NuGet",
        project_markers=("*.csproj", "*.sln"),
        high_value_filename_patterns=(
            r"Startup\.cs$",
            r"Program\.cs$",
            r"appsettings.*\.json$",
            r".*Controller\.cs$",
            r".*Handler\.cs$",
            r".*Repository\.cs$",
            r".*AuthenticationHandler\.cs$",
            r".*Encryptor\.cs$",
            r".*KeyDeriver\.cs$",
            r".*TokenGenerator\.cs$",
            r".*Configuration\.cs$",
            r"web\.config$",
        ),
        # Request-handler files: ASP.NET controllers + MediatR request handlers
        handler_file_patterns=(
            r".*Controller\.cs$",
            r".*RequestHandler\.cs$",
        ),
        # Content-level markers confirming the file contains a handler class
        handler_class_markers=(
            r"\[ApiController\]",
            r":\s*Controller\b",
            r":\s*ControllerBase\b",
            r"IRequestHandler<",
            r"\[Http(Get|Post|Put|Delete|Patch)\]",
        ),
        # Auth, session, crypto, middleware, config files
        auth_file_patterns=(
            r"Startup\.cs$",
            r"Program\.cs$",
            r"appsettings.*\.json$",
            r"web\.config$",
            r".*Authentication.*\.cs$",
            r".*Authorization.*\.cs$",
            r".*Middleware.*\.cs$",
            r".*Encryptor\.cs$",
            r".*KeyDeriver\.cs$",
            r".*TokenGenerator\.cs$",
        ),
        ignore_dirs=_COMMON_IGNORES,
        vulnerability_hints=(
            "- ASP.NET Core: missing [Authorize], disabled antiforgery, "
            "permissive CORS (`AllowAnyOrigin`), `UseDeveloperExceptionPage` in prod.\n"
            "- Crypto: `MD5`, `SHA1`, `RijndaelManaged`, ECB mode, hard-coded keys/IVs, "
            "`new Random()` for security tokens, weak PBKDF2 iteration counts.\n"
            "- Injection: string-concatenated SQL, `SqlCommand` w/ interpolation, "
            "`Process.Start` with user input, `XmlDocument` w/o disabling DTD.\n"
            "- Deserialization: `BinaryFormatter`, `JavaScriptSerializer`, "
            "`TypeNameHandling=All` in JSON.NET.\n"
            "- Secrets in `appsettings.json` / connection strings.\n"
            "- Cookies without `Secure`/`HttpOnly`/`SameSite`."
        ),
    ),
    "python": LanguageProfile(
        name="python",
        extensions=(".py", ".cfg", ".ini", ".toml", ".yml", ".yaml"),
        manifest_files=("requirements.txt", "pyproject.toml", "Pipfile"),
        osv_ecosystem="PyPI",
        project_markers=("manage.py", "pyproject.toml", "setup.py", "requirements.txt"),
        high_value_filename_patterns=(
            r"settings\.py$",
            r"urls\.py$",
            r"views\.py$",
            r"models\.py$",
            r"forms\.py$",
            r"middleware\.py$",
            r"serializers\.py$",
            r"app\.py$",
            r"main\.py$",
            r"wsgi\.py$",
            r"asgi\.py$",
        ),
        handler_file_patterns=(
            r"views\.py$",
            r".*views.*\.py$",
            r".*endpoints.*\.py$",
            r"urls\.py$",
        ),
        handler_class_markers=(
            r"class\s+\w+(View|ViewSet|APIView)\b",
            r"@app\.route\b",
            r"@router\.(get|post|put|delete|patch)\b",
            r"def\s+(get|post|put|delete|patch|dispatch)\s*\(",
        ),
        auth_file_patterns=(
            r"settings\.py$",
            r".*auth.*\.py$",
            r".*middleware.*\.py$",
            r".*permissions.*\.py$",
            r".*serializers.*\.py$",
        ),
        ignore_dirs=_COMMON_IGNORES + ("migrations",),
        vulnerability_hints=(
            "- Django: `DEBUG=True`, `ALLOWED_HOSTS=['*']`, `@csrf_exempt`, "
            "`mark_safe()`, `raw()`/`extra()` SQL, mass-assignment via `**request.POST`.\n"
            "- Flask: `debug=True`, `render_template_string` with user input.\n"
            "- General: `eval`/`exec`, `pickle.loads`, `subprocess(... shell=True)`, "
            "`yaml.load` w/o SafeLoader, hard-coded secrets."
        ),
    ),
    "java": LanguageProfile(
        name="java",
        extensions=(".java", ".xml", ".properties", ".yml", ".yaml"),
        manifest_files=("pom.xml", "build.gradle", "build.gradle.kts"),
        osv_ecosystem="Maven",
        project_markers=("pom.xml", "build.gradle", "build.gradle.kts"),
        high_value_filename_patterns=(
            r".*Application\.java$",
            r".*Controller\.java$",
            r".*Service\.java$",
            r".*Repository\.java$",
            r".*SecurityConfig.*\.java$",
            r".*Filter\.java$",
            r"application(-.*)?\.(properties|ya?ml)$",
            r"web\.xml$",
        ),
        handler_file_patterns=(
            r".*Controller\.java$",
            r".*Resource\.java$",
            r".*Endpoint\.java$",
            r".*Servlet\.java$",
        ),
        handler_class_markers=(
            r"@RestController\b",
            r"@Controller\b",
            r"@RequestMapping\b",
            r"@(Get|Post|Put|Delete|Patch)Mapping\b",
        ),
        auth_file_patterns=(
            r".*SecurityConfig.*\.java$",
            r".*AuthenticationProvider.*\.java$",
            r".*Filter\.java$",
            r".*Application\.java$",
            r"application(-.*)?\.(properties|ya?ml)$",
            r"web\.xml$",
        ),
        ignore_dirs=_COMMON_IGNORES,
        vulnerability_hints=(
            "- Spring Security misconfig (`permitAll`, disabled CSRF, "
            '`@CrossOrigin("*")`).\n'
            "- SQL injection via `Statement` / string-concat JPQL.\n"
            "- `ObjectInputStream.readObject` (insecure deserialization).\n"
            "- `Runtime.exec`, XXE in `DocumentBuilderFactory` w/o feature hardening, "
            'weak crypto (`DES`, `MD5`, `Cipher.getInstance("AES")` defaulting to ECB).'
        ),
    ),
    "javascript": LanguageProfile(
        name="javascript",
        extensions=(".js", ".jsx", ".ts", ".tsx", ".json", ".env"),
        manifest_files=("package.json",),
        osv_ecosystem="npm",
        project_markers=("package.json",),
        high_value_filename_patterns=(
            r"server\.(js|ts)$",
            r"app\.(js|ts)$",
            r"index\.(js|ts)$",
            r".*router.*\.(js|ts)$",
            r".*middleware.*\.(js|ts)$",
            r".*auth.*\.(js|ts)$",
            r"\.env(\..*)?$",
        ),
        handler_file_patterns=(
            r".*router.*\.(js|ts)$",
            r".*routes.*\.(js|ts)$",
            r".*controller.*\.(js|ts)$",
            r".*handler.*\.(js|ts)$",
        ),
        handler_class_markers=(
            r"router\.(get|post|put|delete|patch)\b",
            r"app\.(get|post|put|delete|patch)\b",
            r"export\s+(default\s+)?function\s+\w*[Hh]andler\b",
        ),
        auth_file_patterns=(
            r"server\.(js|ts)$",
            r"app\.(js|ts)$",
            r".*auth.*\.(js|ts)$",
            r".*middleware.*\.(js|ts)$",
            r"\.env(\..*)?$",
        ),
        ignore_dirs=_COMMON_IGNORES,
        vulnerability_hints=(
            "- Express: missing `helmet`, permissive CORS, `eval`, "
            "`child_process.exec` with user input, prototype pollution.\n"
            "- JWT: `algorithm: 'none'`, hard-coded secrets, missing expiry.\n"
            "- React/Next: `dangerouslySetInnerHTML`, SSRF in fetch."
        ),
    ),
    "go": LanguageProfile(
        name="go",
        extensions=(".go", ".mod", ".sum", ".yaml", ".yml"),
        manifest_files=("go.mod",),
        osv_ecosystem="Go",
        project_markers=("go.mod",),
        high_value_filename_patterns=(
            r"main\.go$",
            r".*handler.*\.go$",
            r".*server.*\.go$",
            r".*router.*\.go$",
            r".*auth.*\.go$",
        ),
        handler_file_patterns=(
            r".*handler.*\.go$",
            r".*router.*\.go$",
            r".*server.*\.go$",
        ),
        handler_class_markers=(
            r"func\s+\w*[Hh]andler\b",
            r"http\.HandleFunc\b",
            r"mux\.(Handle|HandleFunc)\b",
        ),
        auth_file_patterns=(
            r"main\.go$",
            r".*auth.*\.go$",
            r".*middleware.*\.go$",
        ),
        ignore_dirs=_COMMON_IGNORES,
        vulnerability_hints=(
            "- `database/sql` string-concat queries, `os/exec` with user input, "
            "`html/template` vs `text/template` for HTML, weak `math/rand` for tokens, "
            "missing TLS verification (`InsecureSkipVerify=true`)."
        ),
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Repo configuration / auto-detection
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class RepoConfig:
    local_path: str  # absolute filesystem path to repo root
    app_root: str  # virtual path inside repo (e.g. "/src" or "/")
    language: str  # key into LANGUAGE_PROFILES
    profile: LanguageProfile = field(init=False)
    manifest_paths: list[str] = field(default_factory=list)  # absolute paths

    def __post_init__(self):
        self.profile = LANGUAGE_PROFILES[self.language]


def _walk_files(root: str, ignore_dirs: Iterable[str]) -> list[str]:
    """Return relative file paths under root, skipping ignored dirs."""
    ignore = set(ignore_dirs)
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignore and not d.startswith(".")]
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            out.append(os.path.relpath(full, root))
    return out


def _glob_match(name: str, pattern: str) -> bool:
    if "*" not in pattern:
        return name == pattern
    regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
    return re.match(regex, name) is not None


def detect_language(local_path: str) -> str:
    """Pick the language with the most source files in the repo."""
    counts: dict[str, int] = {k: 0 for k in LANGUAGE_PROFILES}
    for rel in _walk_files(local_path, _COMMON_IGNORES):
        for lang, prof in LANGUAGE_PROFILES.items():
            if rel.endswith(prof.extensions):
                counts[lang] += 1
                break
    best = max(counts.items(), key=lambda kv: kv[1])
    if best[1] == 0:
        raise RuntimeError(f"No recognised source files under {local_path}")
    return best[0]


def detect_app_root(local_path: str, profile: LanguageProfile) -> str:
    """
    Find the common-ancestor directory of all project markers and return it as
    a virtual path (starts with '/'). Falls back to '/' if no markers found.
    """
    matches: list[str] = []
    for rel in _walk_files(local_path, _COMMON_IGNORES):
        base = os.path.basename(rel)
        for marker in profile.project_markers:
            if _glob_match(base, marker):
                matches.append(os.path.dirname(rel))
                break
    if not matches:
        return "/"
    common = os.path.commonpath(matches) if len(matches) > 1 else matches[0]
    return "/" + common.replace(os.sep, "/") if common else "/"


def find_manifests(local_path: str, profile: LanguageProfile) -> list[str]:
    """Absolute paths of all SCA manifest files in the repo."""
    found: list[str] = []
    for rel in _walk_files(local_path, _COMMON_IGNORES):
        base = os.path.basename(rel)
        for pat in profile.manifest_files:
            if _glob_match(base, pat):
                found.append(os.path.join(local_path, rel))
                break
    return found


def build_repo_config(
    local_path: str | None = None,
    repo_url: str | None = None,
    app_root: str | None = None,
    language: str | None = None,
) -> RepoConfig:
    """Resolve repo on disk (clone if needed) and auto-detect its layout."""
    local_path = local_path or os.environ.get("REPO_PATH")
    repo_url = repo_url or os.environ.get("REPO_URL")
    app_root = app_root or os.environ.get("APP_ROOT")
    language = language or os.environ.get("LANGUAGE")

    if not local_path:
        # Default: clone into ./repo next to this script if a URL was given,
        # otherwise scan the current workspace.
        candidate = os.path.join(SCRIPT_DIR, "repo")
        if repo_url:
            if not os.path.isdir(os.path.join(candidate, ".git")):
                print(f"Cloning {repo_url} -> {candidate}")
                git.Repo.clone_from(repo_url, candidate)
            local_path = candidate
        elif os.path.isdir(os.path.join(candidate, ".git")):
            local_path = candidate
        else:
            local_path = WORKSPACE_ROOT
            print(f"No REPO_URL / REPO_PATH set — scanning workspace: {local_path}")

    local_path = os.path.abspath(local_path)
    if not os.path.isdir(local_path):
        raise FileNotFoundError(f"Repo path does not exist: {local_path}")

    if not language:
        language = detect_language(local_path)
    profile = LANGUAGE_PROFILES[language]

    if not app_root:
        app_root = detect_app_root(local_path, profile)

    cfg = RepoConfig(
        local_path=local_path,
        app_root=app_root,
        language=language,
    )
    cfg.manifest_paths = find_manifests(local_path, profile)

    print(f"Repo:      {cfg.local_path}")
    print(f"Language:  {cfg.language}")
    print(f"App root:  {cfg.app_root}")
    print(f"Manifests: {len(cfg.manifest_paths)} found")
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
# SCA tool — multi-ecosystem
# ─────────────────────────────────────────────────────────────────────────────
def _parse_manifest(path: str, ecosystem: str) -> list[tuple[str, str | None]]:
    """Return [(package, version or None), ...] for a single manifest file."""
    try:
        text = open(path, encoding="utf-8", errors="ignore").read()
    except OSError:
        return []

    entries: list[tuple[str, str | None]] = []
    base = os.path.basename(path)

    if ecosystem == "PyPI":
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for sep in ("==", ">=", "<=", "~=", "!="):
                if sep in line:
                    n, v = line.split(sep, 1)
                    entries.append((n.strip(), v.split(",")[0].strip()))
                    break
            else:
                entries.append((line, None))

    elif ecosystem == "NuGet":
        # PackageReference: <PackageReference Include="X" Version="1.2.3" />
        for m in re.finditer(
            r'PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', text
        ):
            entries.append((m.group(1), m.group(2)))
        # packages.config: <package id="X" version="1.2.3" />
        for m in re.finditer(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', text):
            entries.append((m.group(1), m.group(2)))

    elif ecosystem == "npm":
        if base == "package.json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return []
            for section in ("dependencies", "devDependencies"):
                for n, v in (data.get(section) or {}).items():
                    entries.append((n, str(v).lstrip("^~>=< ")))

    elif ecosystem == "Maven":
        # naive pom.xml parse
        for m in re.finditer(
            r"<dependency>\s*<groupId>([^<]+)</groupId>\s*"
            r"<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>",
            text,
        ):
            entries.append((f"{m.group(1)}:{m.group(2)}", m.group(3)))

    elif ecosystem == "Go":
        for line in text.splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_./-]+)\s+(v[\w.\-+]+)", line)
            if m:
                entries.append((m.group(1), m.group(2)))

    return entries


@tool
def cve_lookup(manifest_paths: str) -> str:
    """
    Query OSV.dev for known vulnerabilities in dependencies.

    Pass a JSON object encoded as a string with keys:
      - "ecosystem": one of "PyPI", "NuGet", "npm", "Maven", "Go"
      - "paths": list of absolute paths to manifest files (e.g. requirements.txt,
                 *.csproj, package.json, pom.xml, go.mod)

    Example: '{"ecosystem":"NuGet","paths":["/repo/src/App/App.csproj"]}'
    """
    try:
        payload = json.loads(manifest_paths)
        ecosystem = payload["ecosystem"]
        paths = payload["paths"]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        return json.dumps({"error": f"Invalid input: {e}"})

    deps: list[tuple[str, str | None]] = []
    for p in paths:
        deps.extend(_parse_manifest(p, ecosystem))

    if not deps:
        return json.dumps({"message": "No dependencies parsed from manifests."})

    results = []
    seen: set[tuple[str, str | None]] = set()
    for name, version in deps:
        if (name, version) in seen:
            continue
        seen.add((name, version))
        body: dict = {"package": {"name": name, "ecosystem": ecosystem}}
        if version:
            body["version"] = version
        try:
            r = requests.post("https://api.osv.dev/v1/query", json=body, timeout=10)
            r.raise_for_status()
            data = r.json()
        except requests.RequestException as exc:
            results.append({"package": name, "version": version, "error": str(exc)})
            continue
        for v in data.get("vulns", []):
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
        return json.dumps({"message": "No known CVEs found."})
    return json.dumps(results, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Static pre-scanner — runs in Python before Phase 1 to classify files
# ─────────────────────────────────────────────────────────────────────────────
def prescan_handlers(cfg: "RepoConfig") -> dict[str, list[str]]:
    """
    Walk the repository on disk and classify source files into:
      - "handlers":  request-handler files (controllers, route handlers, MediatR)
      - "auth":      auth / session / crypto / config files
      - "other_hv":  remaining high-value files from the language profile

    Returns virtual paths (relative to cfg.local_path, prefixed with '/')
    ready for direct use in ``read_file`` calls inside the recon agent.

    Confirmed handlers (those whose content matches ``handler_class_markers``)
    are listed first so the agent reads the most relevant files early.
    """
    prof = cfg.profile

    # Resolve the app directory on the real filesystem
    app_dir = os.path.normpath(os.path.join(cfg.local_path, cfg.app_root.lstrip("/")))
    if not os.path.isdir(app_dir):
        app_dir = cfg.local_path

    def _to_virtual(abs_path: str) -> str:
        rel = os.path.relpath(abs_path, cfg.local_path)
        return "/" + rel.replace(os.sep, "/")

    def _quick_scan(abs_path: str, markers: tuple[str, ...]) -> bool:
        """Read first 8 KB and return True if any marker regex matches."""
        try:
            with open(abs_path, encoding="utf-8", errors="ignore") as fh:
                head = fh.read(8192)
            return any(re.search(m, head) for m in markers)
        except OSError:
            return False

    handler_abs: list[str] = []
    auth_abs: list[str] = []
    other_hv_abs: list[str] = []
    seen: set[str] = set()

    for rel in _walk_files(app_dir, prof.ignore_dirs):
        abs_path = os.path.normpath(os.path.join(app_dir, rel))
        if abs_path in seen:
            continue

        # Priority 1 — request-handler files (by name)
        if any(re.search(p, rel, re.IGNORECASE) for p in prof.handler_file_patterns):
            seen.add(abs_path)
            handler_abs.append(abs_path)
            continue

        # Priority 2 — auth / config / crypto files (by name)
        if any(re.search(p, rel, re.IGNORECASE) for p in prof.auth_file_patterns):
            seen.add(abs_path)
            auth_abs.append(abs_path)
            continue

        # Priority 3 — other high-value files from the legacy profile list
        if any(
            re.search(p, rel, re.IGNORECASE) for p in prof.high_value_filename_patterns
        ):
            seen.add(abs_path)
            other_hv_abs.append(abs_path)

    # Reorder handlers: content-confirmed ones first so the agent reads them early
    confirmed: list[str] = []
    unconfirmed: list[str] = []
    for p in handler_abs:
        (
            confirmed if _quick_scan(p, prof.handler_class_markers) else unconfirmed
        ).append(p)
    handler_abs = confirmed + unconfirmed

    print(
        f"[Prescan] {len(confirmed)} confirmed + {len(unconfirmed)} candidate "
        f"handler file(s), {len(auth_abs)} auth/config file(s), "
        f"{len(other_hv_abs)} other high-value file(s)"
    )
    return {
        "handlers": [_to_virtual(p) for p in handler_abs],
        "auth": [_to_virtual(p) for p in auth_abs],
        "other_hv": [_to_virtual(p) for p in other_hv_abs],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Prompt builders (language-agnostic)
# ─────────────────────────────────────────────────────────────────────────────
def build_recon_prompt(
    cfg: "RepoConfig", prescan: dict[str, list[str]] | None = None
) -> str:
    prof = cfg.profile
    cve_arg = json.dumps({"ecosystem": prof.osv_ecosystem, "paths": cfg.manifest_paths})

    # ── Focused prompt (prescan results available) ────────────────────────────
    if prescan:
        handlers = prescan.get("handlers", [])
        auth = prescan.get("auth", [])
        other_hv = prescan.get("other_hv", [])

        def _fmt(paths: list[str], limit: int) -> str:
            return "\n".join(f"   - `{p}`" for p in paths[:limit]) or "   (none)"

        handler_list = _fmt(handlers, 30)
        auth_list = _fmt(auth, 15)
        other_list = _fmt(other_hv, 8)

        return f"""You are a code reconnaissance agent performing the first step of a SAST pipeline.

Your ONLY job is to map the application and collect raw material — do NOT label
anything as vulnerable yet.

### Target
- Language profile: **{prof.name}**
- App root (virtual): **{cfg.app_root}**

### Permitted tools — you may ONLY call these two
- `read_file` — read a file in full (NO offset/limit)
- `cve_lookup` — call exactly ONCE for SCA

### FORBIDDEN
- `ls`, `glob`, `grep`, `write_file`, `edit_file`.
- Reading any file not listed in the steps below.

### Step 1 — Read ALL request handler files (highest priority)
These files define routes/actions and are the primary attack surface.
For each file, identify:
  a) Every class that is a request handler (look for controller/handler class markers)
  b) Each public action method: HTTP verb, route pattern, parameter bindings
  c) Authorization attributes or guards on the class and each method
  d) Any direct data access, crypto calls, subprocess, deserialization, or file I/O

{handler_list}

### Step 2 — Read security-adjacent files
Authentication, session, cryptography, configuration, and middleware:

{auth_list}

### Step 3 — Other high-value files (read only if not already covered above)

{other_list}

### Step 4 — SCA scan (call exactly once, then STOP)
Call `cve_lookup` with this exact JSON string:
`{cve_arg}`

### What to record in endpoints[]
For every route found, emit one entry:
  {{"route": "<verb> /path/to/route", "handler": "<ClassName.MethodName>", "requires_auth": true/false}}
Set requires_auth=false if there is NO authentication attribute/guard on the method or its class.

### Output Format — respond ONLY with JSON, no prose
```json
{{
  "language": "{prof.name}",
  "app_root": "{cfg.app_root}",
  "app_structure": ["list of key file paths discovered"],
  "config": {{
    "<config-file-name>": "<key settings as JSON or excerpt>"
  }},
  "endpoints": [
    {{"route": "<verb> /path", "handler": "<class.method>", "requires_auth": true}}
  ],
  "code_snippets": {{
    "<relative/path.ext>": "<full file content>"
  }},
  "sca_findings": <raw output from cve_lookup, JSON array>
}}
```
"""

    # ── Fallback: broad-recon prompt (no prescan available) ───────────────────
    ext_glob = "{" + ",".join(e.lstrip(".") for e in prof.extensions) + "}"
    ignore_list = ", ".join(f"`{d}/`" for d in prof.ignore_dirs[:12])
    high_value = "\n".join(
        f"   - regex: `{p}`" for p in prof.high_value_filename_patterns
    )

    return f"""You are a code reconnaissance agent performing the first step of a SAST pipeline.

Your ONLY job is to map the application and collect raw material — do NOT label
anything as vulnerable yet.

### Target
- Language profile: **{prof.name}**
- App root (virtual): **{cfg.app_root}**
- Source extensions: {", ".join(prof.extensions)}

### Permitted tools — you may ONLY call these four
- `ls` — list a directory
- `glob` — find files by pattern
- `read_file` — read a file in full (NO offset/limit)
- `cve_lookup` — call exactly ONCE for SCA

### FORBIDDEN
- `grep`, `write_file`, `edit_file`, paginated reads.

### Exploration rules
- All paths are ABSOLUTE virtual paths starting with `/`.
- `ls(path='{cfg.app_root}')` once.
- `glob(pattern='**/*.{ext_glob}', path='{cfg.app_root}')` once.
- Do NOT enter or list: {ignore_list}.

### High-value files to ALWAYS read if present
{high_value}

### Required steps — execute in order, then STOP
1. `ls(path='{cfg.app_root}')`
2. `glob(pattern='**/*.{ext_glob}', path='{cfg.app_root}')`
3. `read_file` on every file matching a high-value regex above (full content).
4. Focus on request handlers: for each controller/handler file read, identify every
   class that handles HTTP requests, its authorization guards, and its action methods.
5. `cve_lookup` exactly once with this exact JSON string argument:
   `{cve_arg}`
6. Immediately emit the JSON code map below. Do NOT call any tool after `cve_lookup`.

### Output Format — respond ONLY with JSON, no prose
```json
{{
  "language": "{prof.name}",
  "app_root": "{cfg.app_root}",
  "app_structure": ["list of key file paths discovered"],
  "config": {{
    "<config-file-name>": "<key settings as JSON or excerpt>"
  }},
  "endpoints": [
    {{"route": "<verb> /path", "handler": "<class.method>", "requires_auth": true}}
  ],
  "code_snippets": {{
    "<relative/path.ext>": "<full file content>"
  }},
  "sca_findings": <raw output from cve_lookup, JSON array>
}}
```
"""


def build_analysis_prompt(language: str) -> str:
    prof = LANGUAGE_PROFILES[language]
    return f"""You are a vulnerability analyst performing one slice of a SAST pipeline.

You will receive a JSON object containing a SUBSET of files from the recon code map.
Analyse these snippets together with the shared config / SCA context and identify
ALL potential security vulnerabilities. Be thorough — err on inclusion; another
agent will triage false positives later.

Do NOT use the filesystem tools — work only from the provided JSON.

### Universal vulnerability classes
- A01 Broken Access Control (missing authz checks, IDOR, horizontal escalation)
- A02 Cryptographic Failures (weak hashes, hard-coded keys, plaintext secrets,
  weak random for tokens)
- A03 Injection (SQL/NoSQL/command/LDAP/XPath, template injection)
- A04 Insecure Design
- A05 Security Misconfiguration (debug flags, permissive CORS, wildcard hosts,
  missing security headers/cookies)
- A06 Vulnerable & Outdated Components — pull from `sca_findings`
- A07 Identification & Auth Failures (weak password policy, missing rate limit,
  insecure sessions/JWT)
- A08 Software & Data Integrity Failures (unsafe deserialization, mass-assignment)
- A09 Security Logging Failures
- A10 SSRF

### {prof.name}-specific patterns to look for
{prof.vulnerability_hints}

### Output Format — respond ONLY with a JSON array, no prose
```json
[
  {{
    "file": "<relative path>",
    "line": <estimated line number or null>,
    "pattern": "<the exact code or setting that triggered this>",
    "vulnerability_class": "A0X - <Name>",
    "description": "<what is wrong and why it matters>",
    "source": "sast | sca"
  }}
]
```
"""


REPORT_PROMPT_TEMPLATE = """You are a senior application security engineer performing the final triage step.

You will receive a JSON array of candidate findings from multiple analysis workers.
Your job is to:
1. Deduplicate findings reported by multiple chunks.
2. Remove false positives (e.g. neutralised by downstream sanitisation).
3. Assign accurate severity: Critical / High / Medium / Low.
4. Write a concrete attack scenario for each confirmed finding.
5. Write a specific remediation (code change, config setting, or library swap).

You MAY use the filesystem tools to verify a finding if you are unsure.

### Output Format — respond ONLY with the JSON report, no prose
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
def _sev_badge(sev: str) -> str:
    return sev.upper()


def save_report(parsed: dict, run_ts: datetime, cfg: RepoConfig) -> tuple[str, str]:
    """Write findings/sast_<ts>.md and .json under the security/ folder."""
    os.makedirs(FINDINGS_DIR, exist_ok=True)
    slug = run_ts.strftime("%Y-%m-%d_%H-%M-%S")
    md_path = os.path.join(FINDINGS_DIR, f"sast_{slug}.md")
    json_path = os.path.join(FINDINGS_DIR, f"sast_{slug}.json")

    summary = parsed.get("summary", {})
    findings = parsed.get("findings", [])

    lines = [
        "# SAST Security Report",
        "",
        f"**Run:** {run_ts.strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Target:** `{cfg.local_path}` (root `{cfg.app_root}`)  ",
        f"**Language:** {cfg.language}  ",
        f"**Model:** {_MODEL_ID}",
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
            "```",
            f"{(f.get('evidence') or '').strip()}",
            "```",
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
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(parsed, fh, indent=2)
    return md_path, json_path


# ─────────────────────────────────────────────────────────────────────────────
# Phase runners
# ─────────────────────────────────────────────────────────────────────────────
def _make_backend(cfg: RepoConfig) -> FilesystemBackend:
    return FilesystemBackend(root_dir=cfg.local_path, virtual_mode=True)


def run_phase(
    phase_name: str,
    system_prompt: str,
    task: str,
    backend: FilesystemBackend,
    extra_tools: list | None = None,
) -> str:
    """Run an agent-driven phase (Phase 1 / Phase 3)."""
    print(f"\n[{phase_name}] Starting...")
    agent = create_deep_agent(
        model=llm,
        tools=extra_tools or [],
        backend=backend,
        skills=[skills_dir],
        system_prompt=system_prompt,
    )
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


def _llm_call(system_prompt: str, task: str, label: str = "") -> str:
    """
    Streaming LLM call with per-token progress dots and automatic retry.

    Uses ``llm.stream()`` so tokens arrive incrementally — no silent hang.
    Transient Bedrock errors (internalServerException, throttlingException,
    serviceUnavailableException) are retried up to _LLM_MAX_RETRIES times
    with exponential back-off.  Mid-stream failures reset the accumulator
    so the retry starts clean.

    Thread-safe: every print is prefixed with the chunk label.
    """
    import time

    # Transient Bedrock error codes that are safe to retry
    _RETRYABLE = {
        "internalServerException",
        "throttlingException",
        "serviceUnavailableException",
        "ModelStreamErrorException",
    }
    _LLM_MAX_RETRIES = 3
    _LLM_RETRY_BASE_DELAY = 5  # seconds; doubled each attempt (5 → 10 → 20)

    msgs = [SystemMessage(content=system_prompt), HumanMessage(content=task)]
    prefix = f"  [{label}] " if label else "  "

    for attempt in range(_LLM_MAX_RETRIES):
        parts: list[str] = []
        token_count = 0
        last_milestone = 0
        t0 = time.monotonic()

        try:
            print(f"{prefix}streaming", end="", flush=True)
            for chunk in llm.stream(msgs):
                # ChatBedrockConverse yields content as either a plain str or a list of
                # content-block dicts: [{"type": "text", "text": "..."}].  Handle both.
                raw = chunk.content if hasattr(chunk, "content") else ""
                if isinstance(raw, list):
                    text = "".join(
                        block.get("text", "") if isinstance(block, dict) else str(block)
                        for block in raw
                    )
                elif isinstance(raw, str):
                    text = raw
                else:
                    text = str(raw)

                if text:
                    parts.append(text)
                    token_count += len(text.split())
                    # Heartbeat every ~50 approximate tokens
                    if token_count - last_milestone >= 50:
                        last_milestone = token_count
                        elapsed = time.monotonic() - t0
                        print(
                            f"\n{prefix}  ~{token_count} tokens ({elapsed:.0f}s)",
                            end="",
                            flush=True,
                        )

            elapsed = time.monotonic() - t0
            print(f"\n{prefix}done (~{token_count} tokens, {elapsed:.1f}s)", flush=True)
            return "".join(parts)

        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _RETRYABLE and attempt < _LLM_MAX_RETRIES - 1:
                delay = _LLM_RETRY_BASE_DELAY * (2**attempt)
                print(
                    f"\n{prefix}transient error ({code}), retrying in {delay}s "
                    f"(attempt {attempt + 1}/{_LLM_MAX_RETRIES})",
                    flush=True,
                )
                time.sleep(delay)
                continue
            # Non-retryable or final attempt — re-raise so _run_one logs it
            raise


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — chunked, concurrent analysis
# ─────────────────────────────────────────────────────────────────────────────
def _strip_code_fence(text: str) -> str:
    s = text.strip()
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```$", "", s)
    return s.strip()


def _parse_recon_json(recon_output: str) -> dict:
    raw = _strip_code_fence(recon_output)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if not m:
            raise
        return json.loads(m.group(0))


def _chunk_files(files: dict[str, str], chunk_size: int) -> list[dict[str, str]]:
    items = list(files.items())
    return [dict(items[i : i + chunk_size]) for i in range(0, len(items), chunk_size)]


def run_analysis_concurrent(
    code_map: dict,
    language: str,
    workers: int,
    chunk_files: int,
) -> list[dict]:
    """
    Split `code_map["code_snippets"]` into chunks of `chunk_files` files each
    and submit each chunk to an analysis LLM call in a thread pool of
    `workers`. Returns the merged + locally-deduped list of candidate findings.
    """
    snippets: dict[str, str] = code_map.get("code_snippets", {}) or {}
    config_blob = code_map.get("config", {})
    sca = code_map.get("sca_findings", [])

    chunks = _chunk_files(snippets, chunk_files)
    if not chunks:
        chunks = [{}]
    print(
        f"[Phase 2] Splitting {len(snippets)} files into {len(chunks)} chunk(s) "
        f"of up to {chunk_files} files each, {workers} concurrent workers."
    )

    system_prompt = build_analysis_prompt(language)
    sca_chunk_index = 0  # SCA findings analysed exactly once

    def _build_task(idx: int, chunk: dict[str, str]) -> str:
        partial_map = {
            "language": language,
            "app_root": code_map.get("app_root"),
            "config": config_blob,
            "code_snippets": chunk,
            "sca_findings": sca if idx == sca_chunk_index else [],
            "_chunk_info": f"chunk {idx + 1} of {len(chunks)}",
        }
        return (
            "Below is a SUBSET of the recon code map. Analyse only these files "
            "(plus the shared config / SCA findings) and return the JSON "
            "candidate findings array.\n\n--- CODE MAP CHUNK ---\n"
            + json.dumps(partial_map, indent=2)
        )

    def _run_one(idx: int, chunk: dict[str, str]) -> list[dict]:
        label = f"chunk {idx + 1}/{len(chunks)}"
        print(f"  [{label}] -> LLM ({len(chunk)} files)")
        try:
            raw = _llm_call(system_prompt, _build_task(idx, chunk), label=label)
        except Exception as exc:
            print(f"  [{label}] ERROR: {exc}")
            return []
        text = _strip_code_fence(raw)
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            m = re.search(r"\[.*\]", text, re.DOTALL)
            if not m:
                print(f"  [{label}] WARN: no JSON array in response")
                return []
            try:
                parsed = json.loads(m.group(0))
            except json.JSONDecodeError as e:
                print(f"  [{label}] WARN: JSON parse failed ({e})")
                return []
        if isinstance(parsed, dict):
            parsed = parsed.get("findings") or parsed.get("candidates") or []
        if not isinstance(parsed, list):
            return []
        print(f"  [{label}] <- {len(parsed)} candidate(s)")
        return parsed

    all_findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_run_one, i, chunk): i for i, chunk in enumerate(chunks)}
        for fut in as_completed(futures):
            all_findings.extend(fut.result())

    # Light dedup on (file, pattern, vulnerability_class)
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for f in all_findings:
        key = (
            f.get("file"),
            (f.get("pattern") or "")[:120],
            f.get("vulnerability_class"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    print(
        f"[Phase 2] Collected {len(all_findings)} candidate(s) "
        f"-> {len(deduped)} after local dedup."
    )
    return deduped


# ─────────────────────────────────────────────────────────────────────────────
# Main pipeline
# ─────────────────────────────────────────────────────────────────────────────
def run_pipeline(
    local_path: str | None = None,
    repo_url: str | None = None,
    app_root: str | None = None,
    language: str | None = None,
) -> None:
    run_ts = datetime.now()
    print("DeepAgent SAST — language-agnostic pipeline")
    print("=" * 60)
    print(f"Model:     {_MODEL_ID}")

    cfg = build_repo_config(local_path, repo_url, app_root, language)
    backend = _make_backend(cfg)

    # ── Pre-scan: classify files without LLM ────────────────────────────────
    prescan = prescan_handlers(cfg)

    # ── Phase 1: Recon ───────────────────────────────────────────────────────
    recon_prompt = build_recon_prompt(cfg, prescan=prescan)
    recon_task = (
        f"Perform reconnaissance on the {cfg.language} app rooted at "
        f"`{cfg.app_root}`. Follow your system prompt exactly and emit a JSON "
        f"code map. SCA manifests: {cfg.manifest_paths}."
    )
    recon_result = run_phase(
        "Phase 1 — Recon",
        recon_prompt,
        recon_task,
        backend=backend,
        extra_tools=[cve_lookup],
    )

    try:
        code_map = _parse_recon_json(recon_result)
    except json.JSONDecodeError as e:
        print(f"[Phase 1] FATAL: recon output is not valid JSON ({e})")
        print(recon_result[:2000])
        return

    # ── Phase 2: Concurrent Analysis ─────────────────────────────────────────
    workers = int(os.environ.get("ANALYSIS_WORKERS", "8"))
    chunk_files = int(os.environ.get("ANALYSIS_CHUNK_FILES", "3"))
    candidate_findings = run_analysis_concurrent(
        code_map, cfg.language, workers=workers, chunk_files=chunk_files
    )

    # ── Phase 3: Triage & Report ─────────────────────────────────────────────
    report_task = (
        "Below is the merged list of candidate findings produced by parallel "
        "analysis workers. Triage them and produce the final security report.\n\n"
        "--- CANDIDATE FINDINGS ---\n" + json.dumps(candidate_findings, indent=2)
    )
    report_result = run_phase(
        "Phase 3 — Report",
        REPORT_PROMPT_TEMPLATE,
        report_task,
        backend=backend,
    )

    # ── Print + persist ──────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("FINAL SECURITY REPORT:")
    raw = _strip_code_fence(report_result)
    parsed = None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                parsed = json.loads(m.group(0))
            except json.JSONDecodeError:
                parsed = None

    if not parsed:
        print(report_result)
        print("\n[WARNING] Could not parse report JSON — skipping file save.")
        return

    summary = parsed.get("summary", {})
    print(
        f"\nSummary: {summary.get('total_findings', '?')} findings "
        f"| Critical: {summary.get('critical', 0)} "
        f"| High: {summary.get('high', 0)} "
        f"| Medium: {summary.get('medium', 0)} "
        f"| Low: {summary.get('low', 0)}"
    )
    for finding in parsed.get("findings", []):
        sev = finding.get("severity", "").upper()
        print(f"\n[{sev}] {finding.get('id')} — {finding.get('title')}")
        print(f"  File     : {finding.get('file')} (line {finding.get('line')})")
        print(
            f"  OWASP    : {finding.get('owasp_category')}  |  "
            f"CWE: {finding.get('cwe')}"
        )
        print(f"  Evidence : {(finding.get('evidence') or '').strip()}")
        print(f"  Impact   : {finding.get('attack_scenario', '')}")
        print(f"  Fix      : {finding.get('remediation', '')}")

    md_path, json_path = save_report(parsed, run_ts, cfg)
    print(f"\nReport saved:\n  Markdown : {md_path}\n  JSON     : {json_path}")


if __name__ == "__main__":
    run_pipeline()
