"""
threat_modelling.py — Language-agnostic STRIDE + OWASP Top 10 threat model.

Scans a source directory, builds (or loads from cache) a FAISS vector index,
then runs an LLM chain to produce a structured threat model and writes the
output to:
    security/findings/threat_model_<timestamp>.md

Usage:
    python security/threat_modelling.py
    python security/threat_modelling.py --source-dir ./src --language csharp
    python security/threat_modelling.py --source-dir ./src --rebuild

Env overrides (all optional):
    SOURCE_DIR        Path to the source directory to scan
                      (default: <workspace_root>/src)
    LANGUAGE          Force language profile (csharp|python|java|javascript|go)
    FAISS_PATH        Override FAISS index directory path (auto-derived otherwise)
    REBUILD_INDEX     Set to "1" to force rebuild the FAISS index from source
    BEDROCK_MODEL_ID  Bedrock model ID
                      (default: qwen.qwen3-coder-30b-a3b-v1:0)
    BEDROCK_REGION    AWS region override (default: from ~/.aws/config)
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime

os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"  # Fix for OpenMP on macOS

import boto3
from botocore.config import Config
from dotenv import load_dotenv
from langchain_aws import BedrockEmbeddings, ChatBedrockConverse
from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableLambda, RunnablePassthrough
from langchain_text_splitters import RecursiveCharacterTextSplitter

load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE_ROOT = os.path.dirname(SCRIPT_DIR)
FINDINGS_DIR = os.path.join(SCRIPT_DIR, "findings")

os.makedirs(FINDINGS_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Language profiles
# ─────────────────────────────────────────────────────────────────────────────
_COMMON_IGNORES: frozenset[str] = frozenset({
    ".git", "node_modules", "bin", "obj", "dist", "build", "out", "target",
    "__pycache__", ".venv", "venv", ".idea", ".vscode", "vendor", "Pods",
    "static", "assets", "media", "uploads", "fixtures", "htmlcov", "coverage",
    "tests", "test", "__tests__", "docs", ".next", ".nuxt",
})

# Each profile: extensions, vulnerability_hints, knowledge_base
LANGUAGE_PROFILES: dict[str, dict] = {
    "csharp": {
        "extensions": (".cs", ".cshtml", ".razor", ".config", ".json"),
        "project_markers": ("*.csproj", "*.sln"),
        "knowledge_base": """\
## .NET / ASP.NET Core Security Controls Reference

### Authentication & Authorization
- `[Authorize]` attribute enforces authentication on controllers/actions.
- `AddAuthentication()` / `AddAuthorization()` in `Startup.cs` or `Program.cs`.
- Custom `AuthenticationHandler`: must validate tokens using constant-time comparison.
- Cookie auth: requires `HttpOnly=true`, `Secure=true`, `SameSite=Strict`.

### CSRF Protection
- ASP.NET Core generates anti-forgery tokens automatically for Razor pages.
- `services.AddAntiforgery()` + `[ValidateAntiForgeryToken]` on unsafe (POST/PUT/DELETE) actions.
- `[ApiController]` endpoints are exempt but must use token-based CSRF headers or SameSite cookies.

### CORS
- Permissive CORS (`AllowAnyOrigin`) is dangerous in authenticated apps.
- Configured via `UseCors` in the middleware pipeline; restrict to known, explicit origins.

### Cryptography
- Recommended: `Aes.Create()` with GCM or CBC + random IV, `Rfc2898DeriveBytes` (PBKDF2)
  with >= 100,000 iterations (NIST minimum) and SHA-256 PRF.
- Avoid: `MD5`, `SHA1`, `RijndaelManaged`, ECB mode, static IVs, `new Random()` for secrets.

### Input Validation
- Use model binding (`[FromBody]`, `[FromQuery]`) with `ModelState.IsValid` checks.
- Avoid string-concatenated SQL; use parameterized `SqlCommand` with `@param` placeholders.
- `HtmlEncoder.Default.Encode()` for output encoding; Razor auto-encodes by default.

### Session & Tokens
- JWTs: use HTTPS only, short expiry, strong HMAC-SHA256 or RSA signing keys.
- Do not store sensitive data in session cookies; prefer server-side session IDs.

### Secrets Management
- Never commit secrets to `appsettings.json`; use Azure Key Vault, User Secrets (dev),
  or environment variables.
- Connection strings in plaintext config are a critical finding.

### Logging & Monitoring
- Sensitive data (passwords, tokens, PII) must never appear in logs.
- Use `ILogger<T>` for structured logging; avoid `Console.WriteLine` for security events.
- Log authentication successes/failures, access control denials, and data mutations.
""",
        "vulnerability_hints": (
            "- ASP.NET Core: missing [Authorize], disabled antiforgery, "
            "permissive CORS (AllowAnyOrigin), UseDeveloperExceptionPage in prod.\n"
            "- Crypto: MD5, SHA1, RijndaelManaged, ECB mode, static IVs, "
            "new Random() for tokens, weak PBKDF2 iteration counts (<100,000).\n"
            "- Injection: string-concatenated SQL, SqlCommand with interpolation, "
            "Process.Start with user input, XmlDocument without DTD disabling.\n"
            "- Deserialization: BinaryFormatter, JavaScriptSerializer, TypeNameHandling=All.\n"
            "- Secrets in appsettings.json or hardcoded connection strings.\n"
            "- Cookies without Secure/HttpOnly/SameSite flags.\n"
            "- Overly broad exception handlers swallowing security exceptions."
        ),
    },
    "python": {
        "extensions": (".py", ".cfg", ".ini", ".toml", ".yml", ".yaml"),
        "project_markers": ("manage.py", "pyproject.toml", "setup.py", "requirements.txt"),
        "knowledge_base": """\
## Python Web Framework Security Controls Reference

### Django
- `DEBUG=False` in production; `ALLOWED_HOSTS` must not be `['*']`.
- CSRF: built-in middleware active by default. Never use `@csrf_exempt` on sensitive views.
- ORM: use `filter()` / `get()` instead of `raw()` / `extra()` for SQL safety.
- `mark_safe()` with user input leads to XSS; always sanitise first.
- `SECRET_KEY`: must be random (50+ chars), stored as an env var.

### Flask
- `debug=False` in production.
- `render_template_string` with user input leads to SSTI.
- Use `flask-wtf` for CSRF protection; `flask-login` for session management.

### FastAPI
- Use `HTTPBearer` / `OAuth2PasswordBearer` for auth.
- Rate-limit via `slowapi` or a reverse proxy.
- Always validate `Content-Type` for file upload endpoints.

### General Python
- Avoid: `eval`/`exec`, `pickle.loads`, `subprocess(..., shell=True)`,
  `yaml.load` without `SafeLoader`, `os.system`.
- Use `secrets` module for tokens; never use `random`.
- Parameterise DB queries; use SQLAlchemy ORM or `%s` / `?` placeholders.
- Validate file paths to prevent directory traversal (`os.path.abspath` + startswith check).
""",
        "vulnerability_hints": (
            "- Django: DEBUG=True, ALLOWED_HOSTS=['*'], @csrf_exempt, "
            "mark_safe() with user input, raw()/extra() SQL, mass assignment.\n"
            "- Flask: debug=True, render_template_string with user input.\n"
            "- General: eval/exec, pickle.loads, subprocess with shell=True, "
            "yaml.load without SafeLoader, hardcoded secrets, path traversal."
        ),
    },
    "java": {
        "extensions": (".java", ".xml", ".properties", ".yml", ".yaml"),
        "project_markers": ("pom.xml", "build.gradle", "build.gradle.kts"),
        "knowledge_base": """\
## Java / Spring Security Controls Reference

### Spring Security
- `SecurityFilterChain` or `WebSecurityConfigurerAdapter`: controls authentication/authorisation.
- CSRF protection enabled by default; disabling without alternative header checks is dangerous.
- `@PreAuthorize` / `@Secured` for method-level authorisation.
- `@CrossOrigin("*")` is too permissive; restrict to explicit origins.

### Authentication
- Passwords: `BCryptPasswordEncoder`. Avoid MD5, SHA1, plain SHA-256.
- JWT: use RS256/ES256; always validate the `alg` header; check `exp` and `iss`.

### Database
- JPA/Hibernate parameterised queries are safe. Avoid `Statement` with string concatenation.
- `@Query` with positional `?1` parameters is safe; dynamic JPQL string build is not.

### Deserialization
- `ObjectInputStream.readObject` with untrusted data is dangerous (RCE).
- Use a deserialization filter or avoid Java serialisation entirely.

### General
- XXE: call `DocumentBuilderFactory.setFeature("...", false)` to disable external entities.
- Weak crypto: `DES`, `Cipher.getInstance("AES")` defaults to ECB mode.
- `Runtime.exec` / `ProcessBuilder` with user input leads to command injection.
- Spring Boot Actuator endpoints should not be publicly exposed without auth.
""",
        "vulnerability_hints": (
            "- Spring Security misconfig (permitAll, disabled CSRF, @CrossOrigin('*')).\n"
            "- SQL injection via Statement / string-concat JPQL.\n"
            "- ObjectInputStream.readObject (insecure deserialization / RCE).\n"
            "- Runtime.exec with user input, XXE in DocumentBuilderFactory, "
            "weak crypto (DES, MD5, AES/ECB default).\n"
            "- Exposed Actuator endpoints without authentication."
        ),
    },
    "javascript": {
        "extensions": (".js", ".jsx", ".ts", ".tsx", ".json", ".env"),
        "project_markers": ("package.json",),
        "knowledge_base": """\
## Node.js / JavaScript Security Controls Reference

### Express.js
- `helmet`: sets secure HTTP headers (X-Content-Type-Options, X-Frame-Options, CSP, etc.).
- `express-rate-limit`: prevents brute-force and DoS.
- CORS: `cors` package with an explicit `origin` allowlist, never `origin: '*'` in prod.
- Body parsing: `express.json()` with a size limit to prevent DoS.

### Authentication
- Passwords: `bcrypt` / `argon2`. Avoid `md5`, `sha1`, or `crypto.createHash` for passwords.
- JWT: `jsonwebtoken` — always validate `alg`, set short `expiresIn`, store secret in env vars.
- Sessions: `express-session` with `secure`, `httpOnly`, `sameSite` cookie flags.

### Input Validation
- `joi`, `zod`, or `express-validator` for schema validation.
- Avoid `eval`, `Function()`, and template literals in dynamic code execution contexts.
- MongoDB: avoid `$where` with untrusted input; use typed query builders.

### Frontend (React / Next.js)
- `dangerouslySetInnerHTML`: only use with content sanitised via `DOMPurify`.
- SSRF: validate and allowlist URLs before passing to `fetch`/`axios` on the server.
- CSP headers should be set to prevent XSS in production.
""",
        "vulnerability_hints": (
            "- Express: missing helmet, permissive CORS, eval, "
            "child_process.exec with user input, prototype pollution.\n"
            "- JWT: algorithm 'none', hardcoded secrets, missing expiry.\n"
            "- React/Next: dangerouslySetInnerHTML, SSRF in server-side fetch.\n"
            "- MongoDB: $where injection, unvalidated query parameters."
        ),
    },
    "go": {
        "extensions": (".go", ".mod", ".sum", ".yaml", ".yml"),
        "project_markers": ("go.mod",),
        "knowledge_base": """\
## Go Security Controls Reference

### HTTP / Web
- `net/http`: set secure response headers manually or via `gorilla/handlers`.
- Rate limiting: `golang.org/x/time/rate` or reverse-proxy middleware.
- TLS: `tls.Config{MinVersion: tls.VersionTLS12}`.

### Authentication
- JWT: `golang-jwt/jwt` — always validate `alg`, check `exp`, use strong HMAC/RSA keys.
- Sessions: `gorilla/sessions` with `Secure`, `HttpOnly`, `SameSite` cookie options.
- Passwords: `golang.org/x/crypto/bcrypt` or `argon2id`.

### Database
- `database/sql`: always use `?` or `$1` placeholders; never concatenate user input.
- `gorm`: use named/positional parameters in Where clauses.

### Input Handling
- `os/exec`: always pass arguments as separate strings, never via shell interpolation.
- Validate and sanitise all external inputs; use `path/filepath.Clean` + prefix check.

### Crypto
- Use `crypto/rand` for all token/nonce generation, never `math/rand`.
- Prefer AES-GCM over AES-CBC; generate a fresh random nonce per encryption.
- Never set `InsecureSkipVerify: true` in production TLS config.
""",
        "vulnerability_hints": (
            "- database/sql string-concat queries, os/exec with user input.\n"
            "- html/template vs text/template: text/template does not escape HTML.\n"
            "- weak math/rand for tokens, InsecureSkipVerify=true in TLS config.\n"
            "- Missing CSRF/CORS controls in HTTP handlers."
        ),
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# File helpers
# ─────────────────────────────────────────────────────────────────────────────
def _walk_source_files(root: str, extensions: tuple[str, ...]) -> list[str]:
    """Return absolute paths of source files under root matching given extensions."""
    result: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in _COMMON_IGNORES and not d.startswith(".")
        ]
        for fname in filenames:
            if any(fname.endswith(ext) for ext in extensions):
                result.append(os.path.join(dirpath, fname))
    return result


def detect_language(source_dir: str) -> str:
    """Detect the dominant language in source_dir by extension frequency."""
    counts: dict[str, int] = {k: 0 for k in LANGUAGE_PROFILES}
    for _dirpath, dirnames, filenames in os.walk(source_dir):
        dirnames[:] = [d for d in dirnames if d not in _COMMON_IGNORES]
        for fname in filenames:
            for lang, prof in LANGUAGE_PROFILES.items():
                if any(fname.endswith(ext) for ext in prof["extensions"]):
                    counts[lang] += 1
                    break
    best = max(counts.items(), key=lambda kv: kv[1])
    if best[1] == 0:
        raise RuntimeError(f"No recognized source files found in: {source_dir}")
    return best[0]


def _load_source_docs(paths: list[str], source_root: str) -> list[Document]:
    """Read source files into LangChain Documents, tagging each with its relative path."""
    docs: list[Document] = []
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            continue
        rel = os.path.relpath(path, source_root)
        docs.append(Document(page_content=content, metadata={"source": rel}))
    return docs


def _format_docs(docs: list[Document]) -> str:
    """Format retrieved documents into a single string with file-path headers."""
    return "\n\n".join(
        f"=== {doc.metadata.get('source', 'unknown')} ===\n{doc.page_content}"
        for doc in docs
    )


# ─────────────────────────────────────────────────────────────────────────────
# FAISS index helpers
# ─────────────────────────────────────────────────────────────────────────────
def build_faiss_index(
    source_dir: str,
    extensions: tuple[str, ...],
    embeddings: BedrockEmbeddings,
    index_path: str,
) -> FAISS:
    """Build a FAISS index from source files and persist it to disk."""
    print(f"Scanning source files in: {source_dir}")
    file_paths = _walk_source_files(source_dir, extensions)
    print(f"  Found {len(file_paths)} source files.")

    docs = _load_source_docs(file_paths, source_dir)
    print(f"  Loaded {len(docs)} documents.")

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=1500,
        chunk_overlap=200,
        add_start_index=True,
    )
    chunks = splitter.split_documents(docs)
    print(f"  Split into {len(chunks)} chunks.")

    print("  Building FAISS index (embedding all chunks — this may take a minute) ...")
    db = FAISS.from_documents(chunks, embeddings)
    db.save_local(index_path)
    print(f"  FAISS index saved to: {index_path}")
    return db


def load_or_build_faiss(
    source_dir: str,
    extensions: tuple[str, ...],
    embeddings: BedrockEmbeddings,
    index_path: str,
    rebuild: bool = False,
) -> FAISS:
    """Load an existing FAISS index or build a new one if absent/stale."""
    index_file = os.path.join(index_path, "index.faiss")
    if not rebuild and os.path.isfile(index_file):
        print(f"Loading existing FAISS index from: {index_path}")
        return FAISS.load_local(
            index_path,
            embeddings,
            allow_dangerous_deserialization=True,
        )
    return build_faiss_index(source_dir, extensions, embeddings, index_path)


# ─────────────────────────────────────────────────────────────────────────────
# Prompt & chain
# ─────────────────────────────────────────────────────────────────────────────
_SYSTEM_PROMPT = """\
You are a senior application security engineer specialising in threat modelling \
and secure code review. You apply industry-standard frameworks — STRIDE and \
OWASP Top 10 (2021) — to produce structured, evidence-grounded security findings.

## Target Language / Framework
{language}

## Frameworks to Apply

**STRIDE** — classify every threat into one or more categories:
- **S**poofing: impersonating a user, service, or component
- **T**ampering: unauthorised modification of data or code
- **R**epudiation: denying actions without audit evidence
- **I**nformation Disclosure: exposing data to unauthorised parties
- **D**enial of Service: degrading or disrupting availability
- **E**levation of Privilege: gaining permissions beyond what is granted

**OWASP Top 10 (2021)** — map findings to:
A01 Broken Access Control | A02 Cryptographic Failures | A03 Injection |
A04 Insecure Design | A05 Security Misconfiguration | A06 Vulnerable Components |
A07 Identification & Authentication Failures | A08 Software & Data Integrity Failures |
A09 Security Logging & Monitoring Failures | A10 SSRF

**Risk Rating** — for each finding assess:
Likelihood (Low / Medium / High) × Impact (Low / Medium / High) → Risk (Low / Medium / High / Critical)

## Known Vulnerability Patterns for This Language
{vulnerability_hints}

## How to Use the Two Inputs
- `<code>` — retrieved snippets from the codebase. Treat these as **primary evidence**.
  Cite specific file paths, function names, or code patterns in every finding.
- `<context>` — security knowledge base of libraries and controls for this language/framework.
  Use it to identify whether expected security controls are **present or conspicuously absent**.

## Output Rules
1. Ground every finding in code evidence — never assert a vulnerability without a code citation.
2. Explicitly call out missing controls (e.g., "No `helmet` import detected").
3. Sort findings by Risk — Critical → High → Medium → Low.
4. When a control is present but misconfigured, quote the misconfigured value.
5. Begin your response with a one-paragraph **Executive Summary**.

<code>
{code}
</code>

<context>
{context}
</context>
"""

_THREAT_MODEL_QUESTION = """\
Analyse the codebase and produce a structured threat model using STRIDE and OWASP Top 10 (2021).
For each section below, cite specific file paths, function names, or code snippets as evidence.

1. **Executive Summary**
   One paragraph summarising the application's purpose, its key security posture, and the top
   3 risk areas identified.

2. **Assets and Trust Boundaries**
   - List key assets (credentials, session tokens, sensitive data, admin functions, API tokens).
   - Identify trust boundaries: unauthenticated zone, authenticated zone, admin-only zone.
   - Describe sensitive data flows (e.g., password handling, token lifecycle, encryption usage).

3. **Threat Actors and Attack Surfaces**
   - Enumerate threat actors (unauthenticated user, authenticated user, insider, automated scanner).
   - List every exposed attack surface (HTTP endpoints, file uploads, WebSocket, admin panel, APIs).
   - Identify entry points most likely to be targeted and why.

4. **STRIDE Threat Analysis**
   For each STRIDE category, identify the top threats with:
   - Specific code evidence (file + function or line)
   - Current control (if any) — quote the relevant code
   - Gap — what is missing or misconfigured
   - OWASP Top 10 (2021) mapping
   - Risk rating: Likelihood × Impact → (Critical / High / Medium / Low)

5. **Security Controls Inventory**
   - List detected security libraries and controls (cross-reference the knowledge base).
   - List controls that are expected but absent or misconfigured.
   - Note any hardcoded secrets, weak crypto, or insecure defaults found in the code.

6. **Prioritised Recommendations**
   - Remediation steps ordered by risk (Critical first).
   - For each fix: what to change, where in the code, OWASP/STRIDE category addressed.
   - Recommend architectural or configuration changes that would broadly reduce the attack surface.
"""


def build_chain(
    retriever,
    llm,
    language: str,
    vulnerability_hints: str,
    context_kb: str,
):
    """Assemble the RAG threat-model chain."""
    prompt = ChatPromptTemplate.from_messages([
        ("system", _SYSTEM_PROMPT),
        ("human", "<question>{question}</question>"),
    ])

    chain = (
        {
            "code": retriever | RunnableLambda(_format_docs),
            "question": RunnablePassthrough(),
            "language": RunnableLambda(lambda _: language),
            "vulnerability_hints": RunnableLambda(lambda _: vulnerability_hints),
            "context": RunnableLambda(lambda _: context_kb),
        }
        | prompt
        | llm
        | StrOutputParser()
    )
    return chain


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Language-agnostic STRIDE + OWASP Top 10 threat model via RAG.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--source-dir",
        default=os.environ.get("SOURCE_DIR", os.path.join(WORKSPACE_ROOT, "src")),
        help="Source directory to scan (default: <workspace_root>/src)",
    )
    parser.add_argument(
        "--language",
        default=os.environ.get("LANGUAGE"),
        choices=list(LANGUAGE_PROFILES.keys()),
        help="Force a language profile (auto-detected if omitted)",
    )
    parser.add_argument(
        "--faiss-path",
        default=os.environ.get("FAISS_PATH"),
        help="Override the FAISS index directory path (auto-derived otherwise)",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        default=os.environ.get("REBUILD_INDEX", "0") == "1",
        help="Force rebuild the FAISS index even if one already exists",
    )
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def run_threat_model(
    source_dir: str | None = None,
    language: str | None = None,
    faiss_path: str | None = None,
    rebuild: bool = False,
) -> str:
    """Run the STRIDE+OWASP threat model pipeline and return the output file path."""
    if source_dir is None:
        source_dir = os.environ.get("SOURCE_DIR", os.path.join(WORKSPACE_ROOT, "src"))
    source_dir = os.path.abspath(source_dir)

    if not os.path.isdir(source_dir):
        print(f"ERROR: source directory not found: {source_dir}", file=sys.stderr)
        sys.exit(1)

    # ── Language detection ────────────────────────────────────────────────
    language = language or os.environ.get("LANGUAGE") or detect_language(source_dir)
    profile = LANGUAGE_PROFILES[language]
    print(f"Language profile : {language}")

    # ── FAISS path ────────────────────────────────────────────────────────
    if faiss_path:
        faiss_path = os.path.abspath(faiss_path)
    else:
        # Derive a stable name from the source directory basename.
        dir_name = os.path.basename(source_dir.rstrip(os.sep)) or "repo"
        faiss_path = os.path.join(SCRIPT_DIR, f"{dir_name}.faiss")

        # Special-case: reuse the pre-built master_password.faiss when scanning
        # the workspace's own src/ directory (avoids redundant re-embedding).
        default_index = os.path.join(SCRIPT_DIR, "master_password.faiss")
        if (
            dir_name == "src"
            and os.path.isfile(os.path.join(default_index, "index.faiss"))
            and not rebuild
        ):
            faiss_path = default_index
            print(f"Reusing existing FAISS index : {faiss_path}")

    # ── AWS / LLM setup ───────────────────────────────────────────────────
    _model_id = os.environ.get("BEDROCK_MODEL_ID", "qwen.qwen3-coder-30b-a3b-v1:0")
    _bedrock_client_kwargs: dict = {
        "config": Config(
            read_timeout=300,
            retries={"max_attempts": 2, "mode": "adaptive"},
        )
    }
    if os.environ.get("BEDROCK_REGION"):
        _bedrock_client_kwargs["region_name"] = os.environ["BEDROCK_REGION"]

    embeddings = BedrockEmbeddings(model_id="amazon.titan-embed-text-v2:0")
    llm = ChatBedrockConverse(
        model_id=_model_id,
        temperature=0.6,
        client=boto3.client("bedrock-runtime", **_bedrock_client_kwargs),
    )

    # ── Vector store ──────────────────────────────────────────────────────
    db = load_or_build_faiss(
        source_dir=source_dir,
        extensions=tuple(profile["extensions"]),
        embeddings=embeddings,
        index_path=faiss_path,
        rebuild=rebuild,
    )
    retriever = db.as_retriever(
        search_type="mmr",
        search_kwargs={"k": 10},
    )

    # ── Chain ─────────────────────────────────────────────────────────────
    chain = build_chain(
        retriever=retriever,
        llm=llm,
        language=language,
        vulnerability_hints=profile["vulnerability_hints"],
        context_kb=profile["knowledge_base"],
    )

    # ── Run and tee output to file ────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_path = os.path.join(FINDINGS_DIR, f"threat_model_{timestamp}.md")

    header = (
        f"# Threat Model Report\n\n"
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"**Source directory:** `{source_dir}`\n"
        f"**Language profile:** `{language}`\n"
        f"**FAISS index:** `{faiss_path}`\n"
        f"**Model:** `{_model_id}`\n\n"
        f"---\n\n"
    )

    sep = "=" * 60
    print(f"\n{sep}")
    print(f"Running threat model for : {source_dir}")
    print(f"Output                   : {output_path}")
    print(f"{sep}\n")
    print(header, end="")

    chunks: list[str] = [header]
    for chunk in chain.stream(_THREAT_MODEL_QUESTION):
        print(chunk, end="", flush=True)
        chunks.append(chunk)

    full_output = "".join(chunks)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(full_output)

    print(f"\n\n{sep}")
    print(f"Threat model saved to: {output_path}")
    print(sep)

    return output_path


def main() -> None:
    args = _parse_args()
    run_threat_model(
        source_dir=args.source_dir,
        language=args.language,
        faiss_path=args.faiss_path,
        rebuild=args.rebuild,
    )


if __name__ == "__main__":
    main()
