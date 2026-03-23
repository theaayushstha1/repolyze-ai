"""Red-team scanning engine — pure static analysis against YAML probe files.

Loads probe YAML files, detects missing protections in agent code, applies
converter transformations (Base64, ROT13, leetspeak), and scores results
with OWASP LLM Top 10 mapping.  No external LLM API calls required.
"""

import base64
import codecs
import os
import re
from pathlib import Path
from typing import Any

import yaml

# ── OWASP LLM Top 10 mapping ─────────────────────────────────────────────

OWASP_LLM_MAP: dict[str, dict[str, str]] = {
    "prompt_injection": {
        "owasp_id": "LLM01",
        "title": "LLM01: Prompt Injection",
        "cwe": "CWE-77",
    },
    "jailbreak": {
        "owasp_id": "LLM01",
        "title": "LLM01: Prompt Injection (Jailbreak)",
        "cwe": "CWE-77",
    },
    "data_exfiltration": {
        "owasp_id": "LLM06",
        "title": "LLM06: Sensitive Information Disclosure",
        "cwe": "CWE-200",
    },
    "tool_abuse": {
        "owasp_id": "LLM07",
        "title": "LLM07: Insecure Plugin Design",
        "cwe": "CWE-862",
    },
    "auth_bypass": {
        "owasp_id": "LLM08",
        "title": "LLM08: Excessive Agency",
        "cwe": "CWE-863",
    },
    "toxic_content": {
        "owasp_id": "LLM02",
        "title": "LLM02: Insecure Output Handling",
        "cwe": "CWE-79",
    },
    "hallucination": {
        "owasp_id": "LLM09",
        "title": "LLM09: Overreliance",
        "cwe": "CWE-1188",
    },
    "multi_turn": {
        "owasp_id": "LLM01",
        "title": "LLM01: Prompt Injection (Multi-Turn)",
        "cwe": "CWE-77",
    },
}

# ── Protection detection patterns ─────────────────────────────────────────

PROTECTION_PATTERNS: dict[str, list[str]] = {
    "input_validation": [
        r"validate|validator|pydantic|BaseModel|schema",
        r"input_check|check_input|sanitize_input|clean_input",
        r"InputGuardrail|before_model_callback|input_filter",
    ],
    "content_filtering": [
        r"content_filter|safety_check|moderation|toxicity",
        r"ContentFilter|SafetyFilter|ModerationCheck",
        r"block_list|deny_list|banned_words|profanity",
    ],
    "output_sanitization": [
        r"output_filter|sanitize_output|OutputGuardrail",
        r"after_model_callback|output_check|response_filter",
        r"escape_html|bleach|markupsafe|sanitize",
    ],
    "rate_limiting": [
        r"rate_limit|ratelimit|throttle|RateLimiter",
        r"slowapi|token_bucket|leaky_bucket|requests_per",
        r"max_requests|cooldown|backoff",
    ],
    "auth_checks": [
        r"auth|authenticate|authorize|permission",
        r"@login_required|@requires_auth|verify_token",
        r"jwt|oauth|api_key_check|session_check",
    ],
    "prompt_isolation": [
        r"system_prompt|system_message|SystemMessage",
        r"delimiter|boundary|separator|fence",
        r"instruction_hierarchy|role_separation",
    ],
    "tool_sandboxing": [
        r"sandbox|allowlist|whitelist|permitted_tools",
        r"tool_guard|restricted|safe_execute",
        r"max_tools|tool_filter|tool_policy",
    ],
}

# ── Category to required protections mapping ──────────────────────────────

CATEGORY_PROTECTIONS: dict[str, list[str]] = {
    "prompt_injection": ["input_validation", "content_filtering", "prompt_isolation"],
    "jailbreak": ["input_validation", "content_filtering", "prompt_isolation"],
    "data_exfiltration": ["output_sanitization", "auth_checks", "content_filtering"],
    "tool_abuse": ["tool_sandboxing", "input_validation", "auth_checks"],
    "auth_bypass": ["auth_checks", "input_validation", "rate_limiting"],
    "toxic_content": ["content_filtering", "output_sanitization"],
    "hallucination": ["output_sanitization", "content_filtering"],
    "multi_turn": [
        "input_validation", "content_filtering", "rate_limiting", "prompt_isolation",
    ],
}

# ── Converters ────────────────────────────────────────────────────────────

LEETSPEAK_TABLE: dict[str, str] = {
    "a": "4", "e": "3", "i": "1", "o": "0", "s": "5",
    "t": "7", "l": "1", "g": "9",
}


def _to_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _to_rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


def _to_leetspeak(text: str) -> str:
    return "".join(LEETSPEAK_TABLE.get(c.lower(), c) for c in text)


CONVERTERS: dict[str, Any] = {
    "base64": _to_base64,
    "rot13": _to_rot13,
    "leetspeak": _to_leetspeak,
}

# ── Probe loading ─────────────────────────────────────────────────────────

_PROBES_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "agents", "agent_safety", "probes",
)


def _resolve_probes_dir() -> str:
    """Resolve the probes directory, trying relative path then absolute."""
    candidate = os.path.normpath(_PROBES_DIR)
    if os.path.isdir(candidate):
        return candidate
    # Fallback for different deployment layouts
    fallback = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..",
                     "agents", "agent_safety", "probes")
    )
    return fallback


def load_probe_files() -> list[dict[str, Any]]:
    """Load all .yaml probe files (excluding redteam-config) and return as list."""
    probes_dir = _resolve_probes_dir()
    probe_data: list[dict[str, Any]] = []

    if not os.path.isdir(probes_dir):
        return probe_data

    for fname in sorted(os.listdir(probes_dir)):
        if not fname.endswith(".yaml") or fname == "redteam-config.yaml":
            continue
        fpath = os.path.join(probes_dir, fname)
        try:
            content = Path(fpath).read_text(encoding="utf-8")
            parsed = yaml.safe_load(content)
            if parsed and isinstance(parsed, dict) and "probes" in parsed:
                probe_data.append(parsed)
        except (OSError, yaml.YAMLError):
            continue

    return probe_data


# ── Protection analysis ───────────────────────────────────────────────────

def _detect_protections(file_content: str) -> dict[str, bool]:
    """Check which protection categories are present in the code."""
    return {
        protection: any(
            re.search(pattern, file_content, re.IGNORECASE)
            for pattern in patterns
        )
        for protection, patterns in PROTECTION_PATTERNS.items()
    }


def _get_missing_protections(
    protections: dict[str, bool], category: str,
) -> list[str]:
    """Return list of missing protections required for a probe category."""
    required = CATEGORY_PROTECTIONS.get(category, [])
    return [p for p in required if not protections.get(p, False)]


# ── Converter-based probe analysis ────────────────────────────────────────

def _check_converter_bypass(
    file_content: str, probe_text: str,
) -> list[dict[str, str]]:
    """Check if converter-transformed probes could bypass filters."""
    bypass_risks: list[dict[str, str]] = []

    has_any_decoding = bool(re.search(
        r"base64\.b64decode|codecs\.decode|rot13|decode\s*\(", file_content,
    ))

    for name, converter_fn in CONVERTERS.items():
        transformed = converter_fn(probe_text[:80])  # truncate for efficiency

        # If code decodes this encoding but lacks input validation
        encoding_present = _code_handles_encoding(file_content, name)
        if encoding_present and not _has_post_decode_validation(file_content):
            bypass_risks.append({
                "converter": name,
                "transformed_sample": transformed[:60],
                "risk": f"Code decodes {name} without post-decode validation",
            })

    if has_any_decoding and not re.search(r"sanitize|validate|filter", file_content):
        bypass_risks.append({
            "converter": "generic",
            "transformed_sample": "",
            "risk": "Code performs decoding without post-decode sanitization",
        })

    return bypass_risks


def _code_handles_encoding(file_content: str, encoding: str) -> bool:
    """Check if code processes a specific encoding type."""
    encoding_patterns = {
        "base64": r"base64|b64decode|b64encode",
        "rot13": r"rot13|rot_13|codecs\.(decode|encode)",
        "leetspeak": r"leet|l33t|substitute|char_map",
    }
    pattern = encoding_patterns.get(encoding, "")
    return bool(re.search(pattern, file_content, re.IGNORECASE)) if pattern else False


def _has_post_decode_validation(file_content: str) -> bool:
    """Check if code validates content after decoding."""
    return bool(re.search(
        r"(decode.*validate|decode.*sanitize|decode.*filter|"
        r"validate.*decode|sanitize.*decode)",
        file_content, re.IGNORECASE | re.DOTALL,
    ))


# ── Finding construction ─────────────────────────────────────────────────

def _make_redteam_finding(
    file_path: str,
    category: str,
    probe_id: str,
    severity: str,
    missing: list[str],
    bypass_risks: list[dict[str, str]],
) -> dict[str, Any]:
    """Build a finding dict matching the standard format."""
    owasp = OWASP_LLM_MAP.get(category, {})
    owasp_title = owasp.get("title", "Unknown")
    cwe = owasp.get("cwe")

    missing_str = ", ".join(missing) if missing else "none"
    bypass_str = "; ".join(r["risk"] for r in bypass_risks) if bypass_risks else ""

    description = (
        f"Agent file lacks protections against {category} attacks "
        f"({owasp_title}). Missing: {missing_str}."
    )
    if bypass_str:
        description += f" Converter bypass risks: {bypass_str}."

    remediation = _build_remediation(category, missing)

    return {
        "scan_id": None,
        "agent_name": "redteam_engine",
        "tool_name": "redteam_probe_scanner",
        "category": f"redteam:{category}",
        "severity": _normalize_severity(severity),
        "confidence": "high" if len(missing) >= 2 else "medium",
        "title": f"Vulnerable to {category} — probe {probe_id}",
        "description": description,
        "file_path": file_path,
        "line_start": 1,
        "line_end": None,
        "code_snippet": None,
        "cwe_id": cwe,
        "cve_id": None,
        "remediation": remediation,
    }


def _normalize_severity(raw: str) -> str:
    """Map probe severity strings to the standard set."""
    mapping = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
    }
    return mapping.get(raw.lower(), "MEDIUM")


def _build_remediation(category: str, missing: list[str]) -> str:
    """Generate actionable remediation advice based on missing protections."""
    advice_map = {
        "input_validation": "Add input validation (e.g., Pydantic models, schema checks).",
        "content_filtering": "Add content filtering / safety guardrails.",
        "output_sanitization": "Add output sanitization before returning responses.",
        "rate_limiting": "Add rate limiting to prevent abuse.",
        "auth_checks": "Add authentication and authorization checks.",
        "prompt_isolation": "Isolate system prompts from user input with clear delimiters.",
        "tool_sandboxing": "Sandbox tool execution with an allowlist of permitted operations.",
    }
    parts = [advice_map.get(m, f"Add {m} protection.") for m in missing]
    if not parts:
        parts = [f"Strengthen defenses against {category} attacks."]
    return " ".join(parts)


# ── Scoring and grading ──────────────────────────────────────────────────

def calculate_redteam_grade(
    total_probes: int, protected_count: int,
) -> str:
    """Calculate A-F grade from probe protection ratio."""
    if total_probes == 0:
        return "A"
    ratio = protected_count / total_probes
    if ratio >= 0.95:
        return "A"
    if ratio >= 0.85:
        return "B"
    if ratio >= 0.70:
        return "C"
    if ratio >= 0.50:
        return "D"
    return "F"


def calculate_redteam_score(
    total_probes: int, protected_count: int,
) -> float:
    """Return protection ratio as a float 0.0 - 1.0."""
    if total_probes == 0:
        return 1.0
    return protected_count / total_probes


# ── Per-file analysis ─────────────────────────────────────────────────────

def _analyze_file_against_probes(
    file_path: str,
    file_content: str,
    probe_files: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int, int]:
    """Analyze a single agent file against all probe categories.

    Aggregates findings by category (one finding per category per file)
    instead of per-probe to avoid excessive noise.

    Returns (findings, total_probes, protected_count).
    """
    protections = _detect_protections(file_content)
    findings: list[dict[str, Any]] = []
    total = 0
    protected = 0

    for probe_file in probe_files:
        category = probe_file.get("category", "unknown")
        probes = probe_file.get("probes", [])
        missing = _get_missing_protections(protections, category)

        probe_count = len(probes)
        total += probe_count

        if not missing:
            protected += probe_count
            continue

        # Check converter bypass once per category (using first probe)
        first_prompt = probes[0].get("prompt", "") if probes else ""
        bypass_risks = _check_converter_bypass(file_content, first_prompt)

        # Take the highest severity from probes in this category
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        worst_severity = max(
            (p.get("severity", "medium") for p in probes),
            key=lambda s: severity_order.get(s.lower(), 0),
            default="medium",
        )

        # Generate ONE finding per category per file
        findings.append(_make_redteam_finding(
            file_path, category,
            f"{category}_{probe_count}_probes",
            worst_severity,
            missing, bypass_risks,
        ))

    return findings, total, protected


# ── Public API ────────────────────────────────────────────────────────────

def _find_agent_files(repo_path: str) -> list[str]:
    """Find Python files that contain agent framework imports."""
    agent_import_re = re.compile(
        r"(^\s*from\s+langchain|^\s*from\s+langgraph|^\s*from\s+crewai|"
        r"^\s*from\s+google\.adk|^\s*from\s+openai\.agents|AgentExecutor|"
        r"LlmAgent|CrewBase)",
        re.MULTILINE,
    )
    # Skip directories that contain detection/analysis code (not real agents)
    skip_dirs = {".git", "node_modules", "__pycache__", "docs",
                 "autoresearch", "tests", "test"}
    agent_files: list[str] = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            try:
                content = Path(fpath).read_text(errors="ignore")
                if agent_import_re.search(content):
                    agent_files.append(fpath)
            except OSError:
                continue

    return agent_files


def run_redteam_scan(
    repo_path: str,
    agent_files: list[str] | None = None,
) -> dict[str, Any]:
    """Run the full red-team static analysis engine.

    Args:
        repo_path: Root of the cloned repository.
        agent_files: Optional pre-detected agent file paths.
                     If None, auto-detects agent files.

    Returns dict with: findings, grade, score, total_probes, protected_count,
                       categories_tested.
    """
    if agent_files is None:
        agent_files = _find_agent_files(repo_path)

    if not agent_files:
        return {
            "findings": [],
            "grade": "A",
            "score": 1.0,
            "total_probes": 0,
            "protected_count": 0,
            "categories_tested": [],
        }

    probe_files = load_probe_files()
    if not probe_files:
        return {
            "findings": [],
            "grade": "A",
            "score": 1.0,
            "total_probes": 0,
            "protected_count": 0,
            "categories_tested": [],
        }

    all_findings: list[dict[str, Any]] = []
    grand_total = 0
    grand_protected = 0

    for fpath in agent_files:
        try:
            content = Path(fpath).read_text(errors="ignore")
        except OSError:
            continue

        findings, total, protected = _analyze_file_against_probes(
            fpath, content, probe_files,
        )
        all_findings.extend(findings)
        grand_total += total
        grand_protected += protected

    categories = sorted({pf.get("category", "") for pf in probe_files})
    grade = calculate_redteam_grade(grand_total, grand_protected)
    score = calculate_redteam_score(grand_total, grand_protected)

    return {
        "findings": all_findings,
        "grade": grade,
        "score": score,
        "total_probes": grand_total,
        "protected_count": grand_protected,
        "categories_tested": categories,
    }
