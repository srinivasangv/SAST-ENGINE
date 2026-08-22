"""Every tunable value in the engine lives here, so nothing is buried in code.

Owner: shared (all members read it, nobody else edits it after Day 1).
"""

import os
from pathlib import Path

# ---------------------------------------------------------------- paths

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
SCANS_DIR = DATA_DIR / "scans"
EXPORTS_DIR = DATA_DIR / "exports"

# ---------------------------------------------------------------- LLM

# Stage 3 can reason with any of these. The engine picks whichever key is
# present, in this order, and falls back to the deterministic offline
# validator when none is. The pipeline always completes -- a demo never dies
# because of a missing key or bad wifi.
#
#   anthropic  ANTHROPIC_API_KEY   Claude, via the official SDK
#   openai     OPENAI_API_KEY      GPT, via a plain HTTPS call
#   offline    -                   deterministic rules

ANTHROPIC_MODEL = "claude-opus-5"
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

# Kept as an alias so older code and docs that say LLM_MODEL still work.
LLM_MODEL = ANTHROPIC_MODEL
LLM_MAX_TOKENS = 2000

ANTHROPIC_KEY_ENV = "ANTHROPIC_API_KEY"
OPENAI_KEY_ENV = "OPENAI_API_KEY"
LLM_API_KEY_ENV = ANTHROPIC_KEY_ENV          # backwards-compatible alias

# Force a provider regardless of which keys are set: anthropic | openai | offline
LLM_PROVIDER_ENV = "LLM_PROVIDER"

# A key in the environment is not proof it works -- ours was present and
# returned 401, and an OpenAI key can authenticate and still be out of quota.
# So this answers "is a provider CONFIGURED", never "will the call succeed".
# The real answer lands on the verdict as `fallback_reason`.


def detect_provider() -> str:
    """Which provider Stage 3 will try, based on the environment."""
    forced = os.environ.get(LLM_PROVIDER_ENV, "").strip().lower()
    if forced in ("anthropic", "openai", "offline"):
        return forced
    if os.environ.get(ANTHROPIC_KEY_ENV, "").strip():
        return "anthropic"
    if os.environ.get(OPENAI_KEY_ENV, "").strip():
        return "openai"
    return "offline"


def llm_model_for(provider: str | None = None) -> str:
    provider = provider or detect_provider()
    if provider == "openai":
        return OPENAI_MODEL
    if provider == "anthropic":
        return ANTHROPIC_MODEL
    return "rule-based fallback"


def llm_available() -> bool:
    """True when some LLM provider is configured (not that it will work)."""
    return detect_provider() != "offline"


def load_dotenv(path: str | None = None) -> None:
    """Read .env.local into the environment if it exists.

    Keys belong in a gitignored file, never in the repository. Anything
    already exported wins, so a shell export still overrides the file.
    """
    location = Path(path) if path else (ROOT / ".env.local")
    if not location.exists():
        return
    for line in location.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        os.environ[name.strip()] = value.strip().strip("\"'")


# ---------------------------------------------------------------- scanning

# Directories we never walk into when discovering source files.
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", "coverage", ".pytest_cache", "vendor",
    "site-packages", ".mypy_cache", ".tox", ".idea", ".vscode",
}

PYTHON_EXTENSIONS = {".py"}
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

MAX_FILE_BYTES = 512 * 1024   # skip anything bigger; it is almost always generated

# ---------------------------------------------------------------- workflow

# How long a finding may stay open before it breaches its SLA.
SLA_HOURS = {
    "critical": 24,
    "high": 72,
    "medium": 168,     # 7 days
    "low": 720,        # 30 days
}

# Who a breached finding escalates to.
SLA_ESCALATION = {
    "critical": "security-lead + engineering-manager",
    "high": "security-lead",
    "medium": "team-lead",
    "low": "backlog-review",
}

# ---------------------------------------------------------------- server

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8000


def ensure_dirs() -> None:
    """Create the runtime data directories if they do not exist yet."""
    for directory in (DATA_DIR, SCANS_DIR, EXPORTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)
