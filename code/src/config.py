"""
config.py — Central configuration for Ghost Data Still Exists agent.
All paths resolved relative to repo root.
"""
import os
from pathlib import Path


# ── Repo layout ──────────────────────────────────────────────────────────────
REPO_ROOT    = Path(__file__).parent.parent.parent          # hackerrank-orchestrate-october26/
DATASET_DIR  = REPO_ROOT / "dataset"
EVIDENCE_DIR = DATASET_DIR / "evidence"
OUTPUT_PATH  = REPO_ROOT / "output.csv"                      # final submission

# ── Dataset files ─────────────────────────────────────────────────────────────
DELETION_REQUESTS_CSV     = DATASET_DIR / "deletion_requests.csv"
SAMPLE_REQUESTS_CSV       = DATASET_DIR / "sample_deletion_requests.csv"
SAMPLE_OUTPUT_CSV         = DATASET_DIR / "sample_output.csv"
USER_IDENTITIES_CSV       = DATASET_DIR / "user_identities.csv"
USER_AUDIT_LOG_CSV        = DATASET_DIR / "user_audit_log.csv"
SYSTEM_ACTIVITY_CSV       = DATASET_DIR / "system_activity.csv"
DELETION_RULES_CSV        = DATASET_DIR / "deletion_rules.csv"
EVIDENCE_FILES_CSV        = DATASET_DIR / "evidence_files.csv"

# ── AI / LLM ──────────────────────────────────────────────────────────────────
def _load_env_key():
    key = os.environ.get("GEMINI_API_KEY", "")
    if key:
        return key.strip()
    # Try reading .env file from repo root
    env_file = REPO_ROOT / ".env"
    if env_file.exists():
        with open(env_file, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith("GEMINI_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""

GEMINI_API_KEY = _load_env_key()
GEMINI_MODEL   = "gemma-4-26b-a4b-it"        # Google Generative Language working model
ENABLE_LLM     = bool(GEMINI_API_KEY)        # disable if no key

# ── Processing ────────────────────────────────────────────────────────────────
LOG_LEVEL = "INFO"
