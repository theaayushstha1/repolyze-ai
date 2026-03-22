"""Tool wrappers for static analysis — semgrep and bandit.

Each function shells out to the respective CLI tool, captures JSON output,
and returns parsed results as immutable data structures.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class StaticFinding:
    """Immutable static analysis finding."""

    file_path: str
    line_number: int
    severity: str
    rule_id: str
    message: str
    tool: str


def semgrep_scan(
    repo_path: str,
    languages: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Run semgrep on the repository and return parsed findings.

    Args:
        repo_path: Path to the repository to scan.
        languages: Optional list of languages to filter rules.

    Returns:
        List of finding dictionaries.
    """
    cmd: list[str] = [
        "semgrep",
        "scan",
        "--json",
        "--config=auto",
        repo_path,
    ]
    if languages:
        for lang in languages:
            cmd.extend(["--lang", lang])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
    )

    if result.returncode not in (0, 1):
        return [{"error": f"semgrep failed: {result.stderr[:500]}"}]

    return _parse_semgrep_output(result.stdout)


def _parse_semgrep_output(raw_output: str) -> list[dict[str, Any]]:
    """Parse semgrep JSON output into finding dictionaries."""
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return [{"error": "Failed to parse semgrep JSON output"}]

    results: list[dict[str, Any]] = []
    for match in data.get("results", []):
        finding = {
            "file_path": match.get("path", ""),
            "line_number": match.get("start", {}).get("line", 0),
            "severity": _normalize_severity(
                match.get("extra", {}).get("severity", "INFO")
            ),
            "rule_id": match.get("check_id", "unknown"),
            "message": match.get("extra", {}).get("message", ""),
            "tool": "semgrep",
        }
        results.append(finding)
    return results


def bandit_scan(repo_path: str) -> list[dict[str, Any]]:
    """Run bandit on Python files in the repository.

    Args:
        repo_path: Path to the repository to scan.

    Returns:
        List of finding dictionaries.
    """
    cmd: list[str] = [
        "bandit",
        "-r",
        repo_path,
        "-f", "json",
        "--severity-level", "low",
        "--confidence-level", "low",
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
    )

    if result.returncode not in (0, 1):
        return [{"error": f"bandit failed: {result.stderr[:500]}"}]

    return _parse_bandit_output(result.stdout)


def _parse_bandit_output(raw_output: str) -> list[dict[str, Any]]:
    """Parse bandit JSON output into finding dictionaries."""
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return [{"error": "Failed to parse bandit JSON output"}]

    results: list[dict[str, Any]] = []
    for issue in data.get("results", []):
        finding = {
            "file_path": issue.get("filename", ""),
            "line_number": issue.get("line_number", 0),
            "severity": _normalize_severity(issue.get("issue_severity", "LOW")),
            "rule_id": issue.get("test_id", "unknown"),
            "message": issue.get("issue_text", ""),
            "tool": "bandit",
        }
        results.append(finding)
    return results


def _normalize_severity(raw: str) -> str:
    """Normalize severity strings to a consistent set."""
    mapping: dict[str, str] = {
        "ERROR": "critical",
        "CRITICAL": "critical",
        "WARNING": "high",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info",
        "NOTE": "info",
    }
    return mapping.get(raw.upper(), "info")
