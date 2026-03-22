"""Static analysis for agent code — checks for common safety issues.

Inspects agent source files for missing guardrails, unsafe tool configs,
system prompt exposure, missing rate limiting, and hardcoded API keys.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AgentFinding:
    """Immutable finding from agent safety static analysis."""

    file_path: str
    line_number: int
    category: str
    severity: str
    message: str
    recommendation: str


# -- Pattern definitions -------------------------------------------------------

_UNSAFE_TOOL_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (r"subprocess\.(run|call|Popen)\s*\(", "shell_exec",
     "Subprocess execution detected — ensure inputs are validated"),
    (r"os\.system\s*\(", "shell_exec",
     "os.system call detected — use subprocess with argument lists instead"),
    (r"eval\s*\(", "code_eval",
     "eval() detected — never evaluate untrusted input"),
    (r"exec\s*\(", "code_eval",
     "exec() detected — never execute untrusted code"),
    (r"open\s*\([^)]*,\s*['\"]w", "file_write",
     "File write detected — validate paths to prevent directory traversal"),
    (r"shutil\.(rmtree|move|copy)", "file_system",
     "File system operation — ensure sandboxed access only"),
)

_API_KEY_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(?:api_key|apikey|api_secret)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
     "Hardcoded API key detected"),
    (r"(?:sk-|pk_live_|rk_live_|AKIA)[A-Za-z0-9]{10,}",
     "Possible hardcoded secret token detected"),
    (r"Bearer\s+[A-Za-z0-9_\-\.]{20,}",
     "Hardcoded Bearer token detected"),
)

_RATE_LIMIT_KEYWORDS: tuple[str, ...] = (
    "rate_limit", "ratelimit", "throttle", "RateLimiter",
    "max_requests", "requests_per_minute",
)

_GUARDRAIL_KEYWORDS: tuple[str, ...] = (
    "guardrail", "content_filter", "safety_check", "input_validator",
    "before_model_callback", "BeforeToolCallback", "InputGuardrail",
)


# -- Analyzers ----------------------------------------------------------------

def check_unsafe_tools(file_path: str, content: str) -> list[AgentFinding]:
    """Check for unsafe tool configurations."""
    findings: list[AgentFinding] = []
    for pattern, category, message in _UNSAFE_TOOL_PATTERNS:
        for match in re.finditer(pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(AgentFinding(
                file_path=file_path,
                line_number=line_num,
                category=f"unsafe_tool:{category}",
                severity="high",
                message=message,
                recommendation="Wrap tool in a sandboxed executor with input validation.",
            ))
    return findings


def check_hardcoded_keys(file_path: str, content: str) -> list[AgentFinding]:
    """Check for hardcoded API keys and secrets."""
    findings: list[AgentFinding] = []
    for pattern, message in _API_KEY_PATTERNS:
        for match in re.finditer(pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(AgentFinding(
                file_path=file_path,
                line_number=line_num,
                category="hardcoded_secret",
                severity="critical",
                message=message,
                recommendation="Use environment variables or a secret manager.",
            ))
    return findings


def check_missing_guardrails(
    file_path: str, content: str,
) -> list[AgentFinding]:
    """Check whether agent files have input guardrails configured."""
    has_agent_def = bool(re.search(
        r"(LlmAgent|Agent|CrewBase|@tool)", content
    ))
    if not has_agent_def:
        return []

    has_guardrail = any(kw in content for kw in _GUARDRAIL_KEYWORDS)
    if has_guardrail:
        return []

    return [AgentFinding(
        file_path=file_path,
        line_number=1,
        category="missing_guardrail",
        severity="high",
        message="Agent definition found without input guardrails.",
        recommendation="Add input validation / content filtering callbacks.",
    )]


def check_system_prompt_exposure(
    file_path: str, content: str,
) -> list[AgentFinding]:
    """Check for system prompt leakage risks."""
    findings: list[AgentFinding] = []
    patterns = (
        r"system_prompt\s*=.*return.*system_prompt",
        r"instruction.*\{.*user_input.*\}",
        r"\.format\(.*user",
    )
    for pat in patterns:
        for match in re.finditer(pat, content, re.DOTALL):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(AgentFinding(
                file_path=file_path,
                line_number=line_num,
                category="prompt_exposure",
                severity="medium",
                message="Potential system prompt exposure via user input interpolation.",
                recommendation="Never interpolate raw user input into system prompts.",
            ))
    return findings


def check_missing_rate_limiting(
    file_path: str, content: str,
) -> list[AgentFinding]:
    """Check if API-facing agent code has rate limiting."""
    is_api_facing = bool(re.search(
        r"(FastAPI|Flask|@app\.(get|post)|router\.(get|post))", content
    ))
    if not is_api_facing:
        return []

    has_rate_limit = any(kw in content for kw in _RATE_LIMIT_KEYWORDS)
    if has_rate_limit:
        return []

    return [AgentFinding(
        file_path=file_path,
        line_number=1,
        category="missing_rate_limit",
        severity="medium",
        message="API-facing code without rate limiting detected.",
        recommendation="Add rate limiting middleware to prevent abuse.",
    )]


def analyze_file(file_path: str) -> list[AgentFinding]:
    """Run all static analysis checks on a single file."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read(512_000)
    except OSError:
        return []

    checks = (
        check_unsafe_tools,
        check_hardcoded_keys,
        check_missing_guardrails,
        check_system_prompt_exposure,
        check_missing_rate_limiting,
    )
    findings: list[AgentFinding] = []
    for check_fn in checks:
        findings.extend(check_fn(file_path, content))
    return findings


def analyze_repo(repo_path: str) -> list[AgentFinding]:
    """Run all static analysis checks across a repository."""
    all_findings: list[AgentFinding] = []
    for root, _dirs, files in os.walk(repo_path):
        for fname in files:
            if fname.endswith(".py"):
                fpath = os.path.join(root, fname)
                all_findings.extend(analyze_file(fpath))
    return all_findings
