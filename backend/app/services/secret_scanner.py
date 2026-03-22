"""TruffleHog-based secret detection with regex fallback.

Attempts to run TruffleHog for deep secret scanning. If TruffleHog is not
installed, falls back to a comprehensive set of regex patterns that detect
common secret types (AWS keys, API tokens, private keys, etc.).
"""

import json
import logging
import os
import re
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

# ── Regex patterns for fallback secret detection ──────────────────────────

SECRET_REGEX_PATTERNS: tuple[tuple[str, str, str, str], ...] = (
    # (pattern, title, severity, description)
    (
        r"AKIA[0-9A-Z]{16}",
        "AWS Access Key ID",
        "CRITICAL",
        "Hardcoded AWS Access Key ID found. Rotate immediately.",
    ),
    (
        r"sk-[A-Za-z0-9]{20,}",
        "OpenAI API Key",
        "CRITICAL",
        "Hardcoded OpenAI API key found. Rotate and use env vars.",
    ),
    (
        r"ghp_[A-Za-z0-9]{36,}",
        "GitHub Personal Access Token",
        "CRITICAL",
        "Hardcoded GitHub PAT found. Revoke and regenerate.",
    ),
    (
        r"github_pat_[A-Za-z0-9_]{22,}",
        "GitHub Fine-Grained Token",
        "CRITICAL",
        "Hardcoded GitHub fine-grained token found. Revoke immediately.",
    ),
    (
        r"sk_live_[A-Za-z0-9]{20,}",
        "Stripe Secret Key",
        "CRITICAL",
        "Hardcoded Stripe secret key found. Rotate immediately.",
    ),
    (
        r"pk_live_[A-Za-z0-9]{20,}",
        "Stripe Publishable Key (Live)",
        "MEDIUM",
        "Stripe live publishable key found. Consider using env vars.",
    ),
    (
        r"-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----",
        "Private Key",
        "CRITICAL",
        "Private key embedded in source code. Move to secure vault.",
    ),
    (
        r"(?:postgresql|mysql|mongodb)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
        "Database Connection String with Credentials",
        "CRITICAL",
        "Database URL with embedded password found. Use env vars.",
    ),
    (
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "JWT Token",
        "HIGH",
        "Hardcoded JWT token found. Tokens should be dynamically issued.",
    ),
    (
        r"(?:api_key|apikey|api_secret|secret_key)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
        "Generic API Key Assignment",
        "HIGH",
        "Hardcoded API key assignment found. Use environment variables.",
    ),
    (
        r"(?:secret|password|passwd|token)\s*=\s*['\"][A-Za-z0-9_!@#$%^&*\-]{8,}['\"]",
        "Generic Secret Assignment",
        "HIGH",
        "Hardcoded secret/password assignment found. Use a secret manager.",
    ),
)

# File extensions to scan for secrets
_SCANNABLE_EXTENSIONS: frozenset[str] = frozenset((
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs",
    ".rb", ".php", ".cs", ".yaml", ".yml", ".json", ".toml",
    ".cfg", ".ini", ".env", ".sh", ".bash", ".zsh", ".conf",
    ".xml", ".properties", ".tf", ".hcl",
))

# Skip directories that are unlikely to contain real secrets
_SKIP_DIRS: frozenset[str] = frozenset((
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".eggs",
))


def run_secret_scan(repo_path: str) -> list[dict[str, Any]]:
    """Run secret detection on the given repo path.

    Tries TruffleHog first; falls back to regex-based scanning.
    Never raises — returns empty list on failure.
    """
    try:
        return _run_trufflehog(repo_path)
    except FileNotFoundError:
        logger.info("TruffleHog not installed, using regex fallback")
    except Exception:
        logger.warning("TruffleHog failed, falling back to regex scanner")

    try:
        return _run_regex_scan(repo_path)
    except Exception:
        logger.exception("Regex secret scanner failed")
        return []


def _run_trufflehog(repo_path: str) -> list[dict[str, Any]]:
    """Execute TruffleHog and parse JSON output."""
    result = subprocess.run(
        ["trufflehog", "filesystem", "--json", "--no-update", repo_path],
        capture_output=True,
        text=True,
        timeout=180,
    )

    findings: list[dict[str, Any]] = []

    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        finding = _parse_trufflehog_line(line)
        if finding is not None:
            findings.append(finding)

    logger.info("TruffleHog found %d secrets", len(findings))
    return findings


def _parse_trufflehog_line(line: str) -> dict[str, Any] | None:
    """Parse a single line of TruffleHog JSON output into a finding."""
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return None

    source_meta = entry.get("SourceMetadata", {}).get("Data", {})
    filesystem = source_meta.get("Filesystem", {})
    file_path = filesystem.get("file", "")

    raw_type = entry.get("DetectorName", entry.get("DetectorType", "unknown"))
    verified = entry.get("Verified", False)

    return {
        "scan_id": None,
        "agent_name": "secret_detection",
        "tool_name": "trufflehog",
        "category": "secret_leak",
        "severity": "CRITICAL" if verified else "HIGH",
        "confidence": "high" if verified else "medium",
        "title": f"Secret detected: {raw_type}",
        "description": (
            f"{'Verified' if verified else 'Potential'} "
            f"{raw_type} secret found by TruffleHog."
        ),
        "file_path": file_path,
        "line_start": filesystem.get("line", None),
        "line_end": None,
        "code_snippet": None,
        "cwe_id": "CWE-798",
        "cve_id": None,
        "remediation": "Rotate the secret immediately and use a secret manager.",
    }


def _run_regex_scan(repo_path: str) -> list[dict[str, Any]]:
    """Walk the repo and scan files for secret patterns using regex."""
    compiled_patterns = tuple(
        (re.compile(pat), title, sev, desc)
        for pat, title, sev, desc in SECRET_REGEX_PATTERNS
    )

    findings: list[dict[str, Any]] = []

    for root, dirs, files in os.walk(repo_path):
        # Prune skippable directories (mutates dirs in-place per os.walk contract)
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]

        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in _SCANNABLE_EXTENSIONS:
                continue

            fpath = os.path.join(root, fname)
            file_findings = _scan_file_for_secrets(fpath, compiled_patterns)
            findings.extend(file_findings)

    logger.info("Regex scanner found %d potential secrets", len(findings))
    return findings


def _scan_file_for_secrets(
    fpath: str,
    compiled_patterns: tuple[tuple[re.Pattern[str], str, str, str], ...],
) -> list[dict[str, Any]]:
    """Scan a single file against all compiled secret patterns."""
    try:
        content = open(fpath, encoding="utf-8", errors="ignore").read()
    except OSError:
        return []

    findings: list[dict[str, Any]] = []

    for regex, title, severity, description in compiled_patterns:
        for match in regex.finditer(content):
            line_num = content[:match.start()].count("\n") + 1
            findings.append({
                "scan_id": None,
                "agent_name": "secret_detection",
                "tool_name": "regex_scanner",
                "category": "secret_leak",
                "severity": severity,
                "confidence": "medium",
                "title": title,
                "description": description,
                "file_path": fpath,
                "line_start": line_num,
                "line_end": None,
                "code_snippet": None,
                "cwe_id": "CWE-798",
                "cve_id": None,
                "remediation": "Remove the secret and use environment variables or a secret manager.",
            })

    return findings
