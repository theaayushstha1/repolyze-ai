"""Real scan orchestrator — clones repos, runs actual scanners, returns findings.

This replaces the demo simulation with real analysis:
1. Clone repo (git clone --depth 1)
2. Detect languages, agent frameworks, MCP servers
3. Run Semgrep static analysis
4. Run agent safety static analyzer
5. Run MCP auditor
6. Aggregate all findings
"""

import logging
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.services.redteam_engine import run_redteam_scan

logger = logging.getLogger(__name__)

# ── Language detection map ──────────────────────────────────────────────────

LANGUAGE_MAP: dict[str, str] = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".tsx": "TypeScript", ".jsx": "JavaScript", ".java": "Java",
    ".go": "Go", ".rs": "Rust", ".rb": "Ruby", ".php": "PHP",
    ".cs": "C#", ".cpp": "C++", ".c": "C", ".swift": "Swift",
    ".kt": "Kotlin", ".sol": "Solidity", ".sh": "Shell",
}

# ── Agent framework patterns ───────────────────────────────────────────────

AGENT_PATTERNS: dict[str, list[str]] = {
    "LangChain": [r"from\s+langchain", r"from\s+langgraph"],
    "CrewAI": [r"from\s+crewai", r"import\s+crewai"],
    "Google ADK": [r"from\s+google\.adk", r"google\.genai"],
    "OpenAI Agents": [r"from\s+openai", r"openai\.agents"],
}

MCP_PATTERNS: list[str] = [
    r"from\s+mcp", r"@mcp\.tool", r"McpServer", r"@server\.tool",
]

# ── Unsafe tool patterns (agent safety) ────────────────────────────────────

UNSAFE_PATTERNS: list[tuple[str, str, str]] = [
    (r"subprocess\.(run|call|Popen)\s*\(", "unsafe_tool:shell_exec",
     "Subprocess execution — ensure inputs are validated"),
    (r"os\.system\s*\(", "unsafe_tool:shell_exec",
     "os.system call — use subprocess with argument lists"),
    (r"eval\s*\(", "unsafe_tool:code_eval",
     "eval() — never evaluate untrusted input"),
    (r"exec\s*\(", "unsafe_tool:code_eval",
     "exec() — never execute untrusted code"),
]

SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"(?:api_key|apikey|api_secret)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
     "Hardcoded API key detected"),
    (r"(?:sk-|pk_live_|rk_live_|AKIA)[A-Za-z0-9]{10,}",
     "Possible hardcoded secret token"),
]

GUARDRAIL_KEYWORDS = (
    "guardrail", "content_filter", "safety_check", "input_validator",
    "InputGuardrail", "before_model_callback",
)


def run_full_scan(repo_url: str, branch: str = "main") -> dict[str, Any]:
    """Execute the complete scan pipeline and return results.

    Returns dict with: scan_meta, languages, agents_detected, mcp_detected,
    findings (list), agent_safety_grade, counts.
    """
    repo_path = None
    started_at = datetime.now(timezone.utc)

    try:
        # 1. Clone
        repo_path = _clone_repo(repo_url, branch)

        # 2. Detect
        languages = _detect_languages(repo_path)
        agents = _detect_agents(repo_path)
        mcp_files = _detect_mcp(repo_path)

        # 3. Run scanners
        findings: list[dict[str, Any]] = []

        semgrep_results = _run_semgrep(repo_path)
        findings.extend(semgrep_results)

        agent_results = _run_agent_safety_scan(repo_path)
        findings.extend(agent_results)

        mcp_results = _run_mcp_audit(repo_path, mcp_files)
        findings.extend(mcp_results)

        # 3b. Run red-team probe analysis on detected agents
        detected_agents = [name for name, found in agents.items() if found]
        redteam_results, redteam_grade = _run_redteam_analysis(
            repo_path, detected_agents,
        )
        findings.extend(redteam_results)

        # 4. Assign IDs and make paths relative
        for f in findings:
            f["id"] = str(uuid.uuid4())
            if f.get("file_path") and repo_path:
                f["file_path"] = os.path.relpath(f["file_path"], repo_path)

        # 5. Count severities
        counts = _count_severities(findings)
        grade = _merge_agent_grades(
            _calculate_agent_grade(agent_results), redteam_grade,
        )

        elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()

        return {
            "status": "completed",
            "languages_detected": languages,
            "agents_detected": [name for name, detected in agents.items() if detected],
            "mcp_detected": len(mcp_files) > 0,
            "findings": findings,
            "total_findings": len(findings),
            "agent_safety_grade": grade,
            "scan_duration_ms": int(elapsed * 1000),
            **counts,
        }

    except Exception as exc:
        logger.exception("Scan failed for %s", repo_url)
        return {
            "status": "failed",
            "error_message": str(exc),
            "findings": [],
            "total_findings": 0,
        }
    finally:
        if repo_path:
            shutil.rmtree(repo_path, ignore_errors=True)


# ── Clone ──────────────────────────────────────────────────────────────────

def _clone_repo(repo_url: str, branch: str) -> str:
    dest = tempfile.mkdtemp(prefix="repolyze_")
    cmd = ["git", "clone", "--depth", "1", "--single-branch"]

    # Try specified branch first, fallback to default
    try:
        subprocess.run(
            [*cmd, "--branch", branch, repo_url, dest],
            check=True, capture_output=True, text=True, timeout=120,
        )
    except subprocess.CalledProcessError:
        shutil.rmtree(dest, ignore_errors=True)
        dest = tempfile.mkdtemp(prefix="repolyze_")
        subprocess.run(
            [*cmd, repo_url, dest],
            check=True, capture_output=True, text=True, timeout=120,
        )

    logger.info("Cloned %s to %s", repo_url, dest)
    return dest


# ── Detection ──────────────────────────────────────────────────────────────

def _detect_languages(repo_path: str) -> list[str]:
    counter: Counter[str] = Counter()
    for root, _dirs, files in os.walk(repo_path):
        if ".git" in root:
            continue
        for fname in files:
            ext = Path(fname).suffix.lower()
            lang = LANGUAGE_MAP.get(ext)
            if lang:
                counter[lang] += 1
    return [lang for lang, _ in counter.most_common(10)]


def _detect_agents(repo_path: str) -> dict[str, bool]:
    detected: dict[str, bool] = {}
    for framework, patterns in AGENT_PATTERNS.items():
        compiled = [re.compile(p) for p in patterns]
        found = False
        for root, _dirs, files in os.walk(repo_path):
            if ".git" in root or found:
                break
            for fname in files:
                if not fname.endswith((".py", ".ts", ".js")):
                    continue
                try:
                    content = Path(os.path.join(root, fname)).read_text(errors="ignore")
                    if any(rx.search(content) for rx in compiled):
                        found = True
                        break
                except OSError:
                    continue
        detected[framework] = found
    return detected


def _detect_mcp(repo_path: str) -> list[str]:
    mcp_files: list[str] = []
    compiled = [re.compile(p) for p in MCP_PATTERNS]
    for root, _dirs, files in os.walk(repo_path):
        if ".git" in root:
            continue
        for fname in files:
            fpath = os.path.join(root, fname)
            if fname in ("mcp.json", "mcp_config.json"):
                mcp_files.append(fpath)
                continue
            if not fname.endswith((".py", ".ts", ".js")):
                continue
            try:
                content = Path(fpath).read_text(errors="ignore")
                if any(rx.search(content) for rx in compiled):
                    mcp_files.append(fpath)
            except OSError:
                continue
    return mcp_files


# ── Semgrep ────────────────────────────────────────────────────────────────

def _run_semgrep(repo_path: str) -> list[dict[str, Any]]:
    """Run Semgrep with auto config and parse results."""
    # Try multiple semgrep paths
    semgrep_cmds = [
        ["semgrep", "scan", "--json", "--config=auto", "--quiet", repo_path],
        [os.path.expanduser("~/AppData/Roaming/Python/Python313/Scripts/semgrep.exe"),
         "scan", "--json", "--config=auto", "--quiet", repo_path],
        ["python", "-m", "semgrep", "scan", "--json", "--config=auto", "--quiet", repo_path],
    ]
    semgrep_env = {
        **os.environ,
        "SEMGREP_SEND_METRICS": "off",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    }
    result = None
    for cmd in semgrep_cmds:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
                env=semgrep_env, encoding="utf-8", errors="replace",
            )
            break
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            logger.warning("Semgrep timed out")
            return []
    if result is None:
        logger.warning("Semgrep not installed, skipping")
        return []

    # Semgrep may output deprecation warnings before JSON — find the JSON block
    raw = result.stdout or ""
    json_start = raw.find("{")
    if json_start == -1:
        logger.warning("Semgrep produced no JSON output")
        return []

    try:
        import json as json_mod
        data = json_mod.loads(raw[json_start:])
    except Exception:
        logger.warning("Failed to parse semgrep JSON output")
        return []

    findings: list[dict[str, Any]] = []
    severity_map = {
        "ERROR": "CRITICAL", "WARNING": "HIGH",
        "INFO": "MEDIUM", "NOTE": "LOW",
    }

    for match in data.get("results", []):
        extra = match.get("extra", {})
        raw_sev = extra.get("severity", "INFO").upper()
        findings.append({
            "scan_id": None,
            "agent_name": "static_analysis",
            "tool_name": "semgrep",
            "category": _map_owasp_category(match.get("check_id", "")),
            "severity": severity_map.get(raw_sev, "MEDIUM"),
            "confidence": "high",
            "title": match.get("check_id", "unknown").split(".")[-1].replace("-", " ").title(),
            "description": extra.get("message", ""),
            "file_path": match.get("path", ""),
            "line_start": match.get("start", {}).get("line"),
            "line_end": match.get("end", {}).get("line"),
            "code_snippet": extra.get("lines", ""),
            "cwe_id": _extract_cwe(extra.get("metadata", {})),
            "cve_id": None,
            "remediation": extra.get("fix", extra.get("message", "")),
        })

    return findings


def _map_owasp_category(check_id: str) -> str:
    check_lower = check_id.lower()
    if "sql" in check_lower or "inject" in check_lower:
        return "injection"
    if "xss" in check_lower or "cross-site" in check_lower:
        return "xss"
    if "auth" in check_lower:
        return "broken_auth"
    if "crypto" in check_lower or "hash" in check_lower:
        return "crypto"
    if "secret" in check_lower or "password" in check_lower:
        return "secret_leak"
    if "path" in check_lower or "traversal" in check_lower:
        return "path_traversal"
    return "security_misconfig"


def _extract_cwe(metadata: dict) -> str | None:
    cwe = metadata.get("cwe", metadata.get("cwe_id"))
    if isinstance(cwe, list) and cwe:
        return str(cwe[0])
    if isinstance(cwe, str):
        return cwe
    return None


# ── Agent Safety ───────────────────────────────────────────────────────────

def _run_agent_safety_scan(repo_path: str) -> list[dict[str, Any]]:
    """Scan for agent safety issues: unsafe tools, secrets, missing guardrails."""
    findings: list[dict[str, Any]] = []

    for root, _dirs, files in os.walk(repo_path):
        if ".git" in root:
            continue
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            try:
                content = Path(fpath).read_text(errors="ignore")
            except OSError:
                continue

            # Check unsafe tool patterns
            for pattern, category, message in UNSAFE_PATTERNS:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count("\n") + 1
                    findings.append(_make_finding(
                        fpath, line_num, "HIGH", category, message,
                        "Wrap in sandboxed executor with input validation.",
                    ))

            # Check hardcoded secrets
            for pattern, message in SECRET_PATTERNS:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count("\n") + 1
                    findings.append(_make_finding(
                        fpath, line_num, "CRITICAL", "hardcoded_secret", message,
                        "Use environment variables or a secret manager.",
                    ))

            # Check missing guardrails — only on files with actual agent framework imports
            has_agent_import = bool(re.search(
                r"(from\s+langchain|from\s+crewai|from\s+google\.adk|"
                r"from\s+openai\.agents|AgentExecutor|LlmAgent|CrewBase)", content
            ))
            if has_agent_import:
                has_guard = any(kw in content for kw in GUARDRAIL_KEYWORDS)
                if not has_guard:
                    findings.append(_make_finding(
                        fpath, 1, "HIGH", "missing_guardrail",
                        "Agent defined without input guardrails.",
                        "Add input validation / content filtering callbacks.",
                    ))

    return findings


def _make_finding(
    file_path: str, line: int, severity: str,
    category: str, title: str, remediation: str,
) -> dict[str, Any]:
    return {
        "scan_id": None,
        "agent_name": "agent_safety",
        "tool_name": "agent_safety_static",
        "category": category,
        "severity": severity,
        "confidence": "high",
        "title": title,
        "description": title,
        "file_path": file_path,
        "line_start": line,
        "line_end": None,
        "code_snippet": None,
        "cwe_id": None,
        "cve_id": None,
        "remediation": remediation,
    }


# ── MCP Audit ──────────────────────────────────────────────────────────────

def _run_mcp_audit(repo_path: str, mcp_files: list[str]) -> list[dict[str, Any]]:
    """Audit MCP server files for security issues."""
    if not mcp_files:
        return []

    findings: list[dict[str, Any]] = []

    shell_patterns = [
        (r"subprocess\.(run|call|Popen)", "Shell execution in MCP tool"),
        (r"os\.system\s*\(", "os.system in MCP tool"),
    ]
    file_patterns = [
        (r"open\s*\([^)]*['\"]w", "Unrestricted file write in MCP tool"),
        (r"shutil\.(rmtree|move)", "Destructive file operation in MCP tool"),
    ]

    for fpath in mcp_files:
        if not fpath.endswith(".py"):
            continue
        try:
            content = Path(fpath).read_text(errors="ignore")
        except OSError:
            continue

        for pattern, message in shell_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append({
                    "scan_id": None, "agent_name": "mcp_auditor",
                    "tool_name": "mcp_auditor", "category": "mcp_security",
                    "severity": "CRITICAL", "confidence": "high",
                    "title": message, "description": message,
                    "file_path": fpath, "line_start": line_num,
                    "line_end": None, "code_snippet": None,
                    "cwe_id": None, "cve_id": None,
                    "remediation": "Sandbox shell execution or use restricted allowlist.",
                })

        for pattern, message in file_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append({
                    "scan_id": None, "agent_name": "mcp_auditor",
                    "tool_name": "mcp_auditor", "category": "mcp_security",
                    "severity": "HIGH", "confidence": "high",
                    "title": message, "description": message,
                    "file_path": fpath, "line_start": line_num,
                    "line_end": None, "code_snippet": None,
                    "cwe_id": None, "cve_id": None,
                    "remediation": "Restrict file ops to sandboxed directory.",
                })

        # Check missing validation
        has_tools = bool(re.search(r"@(mcp\.tool|server\.tool)", content))
        has_validation = bool(re.search(
            r"(validate|sanitize|pydantic|schema|allowlist)", content
        ))
        if has_tools and not has_validation:
            findings.append({
                "scan_id": None, "agent_name": "mcp_auditor",
                "tool_name": "mcp_auditor", "category": "mcp_security",
                "severity": "HIGH", "confidence": "medium",
                "title": "MCP tools without input validation",
                "description": "MCP tools defined without visible input validation.",
                "file_path": fpath, "line_start": 1,
                "line_end": None, "code_snippet": None,
                "cwe_id": "CWE-20", "cve_id": None,
                "remediation": "Add input validation using Pydantic or manual checks.",
            })

    return findings


# ── Helpers ────────────────────────────────────────────────────────────────

def _count_severities(findings: list[dict]) -> dict[str, int]:
    counts = {"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0}
    for f in findings:
        key = f"{f.get('severity', 'INFO').lower()}_count"
        if key in counts:
            counts[key] += 1
    return counts


def _calculate_agent_grade(agent_findings: list[dict]) -> str:
    if not agent_findings:
        return "A"
    crits = sum(1 for f in agent_findings if f.get("severity") == "CRITICAL")
    highs = sum(1 for f in agent_findings if f.get("severity") == "HIGH")
    score = max(0, 100 - (crits * 25) - (highs * 10) - (len(agent_findings) * 2))
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


# ── Red-team analysis ─────────────────────────────────────────────────────

def _run_redteam_analysis(
    repo_path: str, detected_agents: list[str],
) -> tuple[list[dict[str, Any]], str]:
    """Run red-team probe analysis if agents were detected.

    Returns (findings_list, redteam_grade).
    """
    if not detected_agents:
        return [], "A"

    try:
        result = run_redteam_scan(repo_path)
    except Exception:
        logger.exception("Red-team engine failed")
        return [], "A"

    grade = result.get("grade", "A")
    findings = result.get("findings", [])

    logger.info(
        "Red-team scan: %d findings, grade=%s, score=%.2f, probes=%d/%d protected",
        len(findings), grade,
        result.get("score", 0),
        result.get("protected_count", 0),
        result.get("total_probes", 0),
    )

    return findings, grade


def _merge_agent_grades(static_grade: str, redteam_grade: str) -> str:
    """Merge the static analysis grade with the red-team grade (take worst)."""
    grade_order = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}
    static_val = grade_order.get(static_grade, 4)
    redteam_val = grade_order.get(redteam_grade, 4)
    worst_val = min(static_val, redteam_val)
    reverse_map = {v: k for k, v in grade_order.items()}
    return reverse_map.get(worst_val, "A")
