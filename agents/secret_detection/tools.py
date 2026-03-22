"""Tool wrapper for secret detection — TruffleHog.

Shells out to TruffleHog CLI, captures JSON output, and returns
parsed results with secret values safely redacted.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any


def trufflehog_scan(
    repo_path: str,
    scan_history: bool = True,
) -> list[dict[str, Any]]:
    """Run TruffleHog on the repository to detect leaked secrets.

    Args:
        repo_path: Path to the repository to scan.
        scan_history: Whether to scan git history (default True).

    Returns:
        List of finding dictionaries with redacted values.
    """
    cmd: list[str] = [
        "trufflehog",
        "filesystem",
        repo_path,
        "--json",
        "--no-update",
    ]
    if scan_history:
        cmd = [
            "trufflehog",
            "git",
            f"file://{repo_path}",
            "--json",
            "--no-update",
        ]

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=600,
    )

    if result.returncode not in (0, 1):
        return [{"error": f"trufflehog failed: {result.stderr[:500]}"}]

    return _parse_trufflehog_output(result.stdout)


def _parse_trufflehog_output(raw_output: str) -> list[dict[str, Any]]:
    """Parse TruffleHog JSON-lines output into finding dictionaries."""
    results: list[dict[str, Any]] = []

    for line in raw_output.strip().split("\n"):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        finding = {
            "file_path": entry.get("SourceMetadata", {})
            .get("Data", {})
            .get("Filesystem", {})
            .get("file", _extract_git_file(entry)),
            "line_number": entry.get("SourceMetadata", {})
            .get("Data", {})
            .get("Filesystem", {})
            .get("line", 0),
            "secret_type": entry.get("DetectorName", "unknown"),
            "severity": _assess_severity(entry),
            "detector": entry.get("DetectorName", "unknown"),
            "verified": entry.get("Verified", False),
            "redacted_value": _redact_secret(
                entry.get("Raw", "")
            ),
        }
        results.append(finding)

    return results


def _extract_git_file(entry: dict[str, Any]) -> str:
    """Extract file path from git-mode TruffleHog output."""
    git_data = (
        entry.get("SourceMetadata", {})
        .get("Data", {})
        .get("Git", {})
    )
    return git_data.get("file", "unknown")


def _assess_severity(entry: dict[str, Any]) -> str:
    """Assess severity based on verification status and detector type."""
    if entry.get("Verified", False):
        return "critical"

    high_risk_detectors = {
        "AWS", "GCP", "Azure", "Stripe", "GitHub",
        "GitLab", "Slack", "Twilio", "SendGrid",
    }
    detector = entry.get("DetectorName", "")
    if detector in high_risk_detectors:
        return "high"

    return "medium"


def _redact_secret(raw_value: str) -> str:
    """Safely redact a secret value, preserving only first/last chars."""
    if len(raw_value) <= 8:
        return "***REDACTED***"
    return f"{raw_value[:4]}...{raw_value[-4:]}"
