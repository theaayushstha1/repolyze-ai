"""Shared tools for ADK security agents.

These are Python functions that ADK agents can call as tools.
Each function must have a docstring (used as the tool description)
and type-annotated parameters.
"""

import json
import os
from pathlib import Path
from typing import Any

# Module-level state set by the pipeline before agent execution
_repo_path: str = ""
_findings: list[dict[str, Any]] = []
_languages: list[str] = []
_agents_detected: list[str] = []


def configure(
    repo_path: str,
    findings: list[dict[str, Any]],
    languages: list[str],
    agents_detected: list[str],
) -> None:
    """Configure the tools with scan context. Called before agent execution."""
    global _repo_path, _findings, _languages, _agents_detected
    _repo_path = repo_path
    _findings = findings
    _languages = languages
    _agents_detected = agents_detected


# ── Tools for CriticAgent ─────────────────────────────────────────────────

def get_findings_summary() -> str:
    """Get a summary of all findings from static scanners grouped by category and severity."""
    if not _findings:
        return "No findings to review."

    by_category: dict[str, list[str]] = {}
    for f in _findings:
        cat = f.get("category", "unknown")
        sev = f.get("severity", "UNKNOWN")
        title = f.get("title", "untitled")
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(f"[{sev}] {title}")

    lines = [f"Total findings: {len(_findings)}"]
    for cat, items in sorted(by_category.items()):
        lines.append(f"\n{cat} ({len(items)}):")
        for item in items[:5]:
            lines.append(f"  {item}")
        if len(items) > 5:
            lines.append(f"  ... and {len(items) - 5} more")

    return "\n".join(lines)


def get_finding_details(finding_index: int) -> str:
    """Get detailed information about a specific finding by its index (0-based).

    Args:
        finding_index: The index of the finding to retrieve (0-based).
    """
    if finding_index < 0 or finding_index >= len(_findings):
        return f"Invalid index {finding_index}. Valid range: 0-{len(_findings) - 1}"

    f = _findings[finding_index]
    return json.dumps({
        "index": finding_index,
        "title": f.get("title"),
        "severity": f.get("severity"),
        "category": f.get("category"),
        "description": f.get("description"),
        "file_path": f.get("file_path"),
        "line_start": f.get("line_start"),
        "cwe_id": f.get("cwe_id"),
        "remediation": f.get("remediation"),
        "agent_name": f.get("agent_name"),
        "tool_name": f.get("tool_name"),
    }, indent=2)


def get_high_severity_findings() -> str:
    """Get all CRITICAL and HIGH severity findings with their indices for review."""
    high = [
        (i, f) for i, f in enumerate(_findings)
        if f.get("severity") in ("CRITICAL", "HIGH")
    ]
    if not high:
        return "No CRITICAL or HIGH severity findings."

    lines = [f"Found {len(high)} high-severity findings:\n"]
    for i, f in high[:20]:
        lines.append(
            f"[{i}] [{f.get('severity')}] {f.get('title')} "
            f"({f.get('file_path', 'unknown')}:{f.get('line_start', '?')})"
        )
    if len(high) > 20:
        lines.append(f"... and {len(high) - 20} more")

    return "\n".join(lines)


# ── Tools for reading source code ─────────────────────────────────────────

def read_source_file(file_path: str, start_line: int = 1, end_line: int = 50) -> str:
    """Read source code from a file in the scanned repository.

    Args:
        file_path: Relative path to the file within the repository.
        start_line: First line to read (1-based, default 1).
        end_line: Last line to read (1-based, default 50).
    """
    if not _repo_path:
        return "Error: repository not available"

    full_path = os.path.join(_repo_path, file_path)

    if not os.path.isfile(full_path):
        return f"File not found: {file_path}"

    try:
        content = Path(full_path).read_text(errors="ignore")
    except OSError as e:
        return f"Error reading file: {e}"

    lines = content.splitlines()
    start = max(0, start_line - 1)
    end = min(len(lines), end_line)

    numbered = [f"{i+1}: {line}" for i, line in enumerate(lines[start:end], start=start)]
    return f"File: {file_path} (lines {start+1}-{end} of {len(lines)})\n" + "\n".join(numbered)


def list_repository_files(directory: str = ".") -> str:
    """List files in a directory of the scanned repository.

    Args:
        directory: Relative directory path (default is repo root).
    """
    if not _repo_path:
        return "Error: repository not available"

    target = os.path.join(_repo_path, directory)
    if not os.path.isdir(target):
        return f"Directory not found: {directory}"

    skip = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
    result = []

    for item in sorted(os.listdir(target)):
        if item in skip:
            continue
        full = os.path.join(target, item)
        if os.path.isdir(full):
            result.append(f"  {item}/")
        else:
            size = os.path.getsize(full)
            result.append(f"  {item} ({size} bytes)")

    return f"Contents of {directory}/:\n" + "\n".join(result[:50])


# ── Tools for scan metadata ──────────────────────────────────────────────

def get_scan_context() -> str:
    """Get metadata about the repository being scanned including languages and detected frameworks."""
    return json.dumps({
        "languages": _languages,
        "agents_detected": _agents_detected,
        "total_findings": len(_findings),
        "severity_breakdown": {
            sev: sum(1 for f in _findings if f.get("severity") == sev)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        },
    }, indent=2)
