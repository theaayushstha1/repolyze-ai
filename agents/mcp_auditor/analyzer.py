"""Analyze MCP tool definitions for security issues.

Parses MCP server source files and configuration to identify unsafe tool
patterns, missing validation, and excessive permissions.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MCPFinding:
    """Immutable MCP security finding."""

    tool_name: str
    file_path: str
    line_number: int
    severity: str
    category: str
    message: str
    recommendation: str


# -- Unsafe patterns in MCP tool implementations ------------------------------

_SHELL_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"subprocess\.(run|call|Popen)", "Shell command execution in MCP tool"),
    (r"os\.system\s*\(", "os.system call in MCP tool"),
    (r"os\.popen\s*\(", "os.popen call in MCP tool"),
)

_FILE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"open\s*\([^)]*['\"]w", "Unrestricted file write in MCP tool"),
    (r"shutil\.(rmtree|move)", "Destructive file operation in MCP tool"),
    (r"os\.(remove|unlink|rmdir)", "File deletion in MCP tool"),
    (r"pathlib\.Path.*\.write_", "Path write operation in MCP tool"),
)

_VALIDATION_PATTERNS: tuple[str, ...] = (
    r"(validate|sanitize|check_input|verify_path|is_safe)",
    r"(pydantic|schema|validator)",
    r"(whitelist|allowlist|allowed_paths)",
)


def analyze_mcp_tools(repo_path: str) -> list[dict[str, Any]]:
    """Analyze MCP server implementations for security issues.

    Args:
        repo_path: Path to the repository to analyze.

    Returns:
        List of finding dictionaries.
    """
    findings: list[MCPFinding] = []

    mcp_files = _find_mcp_files(repo_path)
    for fpath in mcp_files:
        content = _read_file_safe(fpath)
        findings.extend(_check_shell_usage(fpath, content))
        findings.extend(_check_file_operations(fpath, content))
        findings.extend(_check_missing_validation(fpath, content))
        findings.extend(_check_tool_permissions(fpath, content))

    config_findings = _check_mcp_config(repo_path)
    findings.extend(config_findings)

    return [_finding_to_dict(f) for f in findings]


def _find_mcp_files(repo_path: str) -> list[str]:
    """Find files that contain MCP server/tool definitions."""
    mcp_files: list[str] = []
    mcp_indicators = (
        r"from\s+mcp", r"import\s+mcp", r"@mcp\.tool",
        r"McpServer", r"mcp_server", r"@server\.tool",
    )
    compiled = tuple(re.compile(p) for p in mcp_indicators)

    for root, _dirs, files in os.walk(repo_path):
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            try:
                content = _read_file_safe(fpath)
                if any(rx.search(content) for rx in compiled):
                    mcp_files.append(fpath)
            except OSError:
                continue
    return mcp_files


def _read_file_safe(path: str, max_bytes: int = 256_000) -> str:
    """Read a file safely with a size limit."""
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return fh.read(max_bytes)


def _check_shell_usage(
    fpath: str, content: str,
) -> list[MCPFinding]:
    """Check for shell command execution in MCP tools."""
    findings: list[MCPFinding] = []
    for pattern, message in _SHELL_PATTERNS:
        for match in re.finditer(pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(MCPFinding(
                tool_name=_extract_tool_name(content, match.start()),
                file_path=fpath,
                line_number=line_num,
                severity="critical",
                category="shell_execution",
                message=message,
                recommendation=(
                    "Sandbox shell execution or use a restricted "
                    "command allowlist."
                ),
            ))
    return findings


def _check_file_operations(
    fpath: str, content: str,
) -> list[MCPFinding]:
    """Check for unsafe file operations in MCP tools."""
    findings: list[MCPFinding] = []
    for pattern, message in _FILE_PATTERNS:
        for match in re.finditer(pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(MCPFinding(
                tool_name=_extract_tool_name(content, match.start()),
                file_path=fpath,
                line_number=line_num,
                severity="high",
                category="unsafe_file_access",
                message=message,
                recommendation=(
                    "Restrict file operations to a sandboxed directory. "
                    "Validate all paths against a whitelist."
                ),
            ))
    return findings


def _check_missing_validation(
    fpath: str, content: str,
) -> list[MCPFinding]:
    """Check whether MCP tool functions have input validation."""
    tool_defs = list(re.finditer(r"@(mcp\.tool|server\.tool)", content))
    if not tool_defs:
        return []

    has_validation = any(
        re.search(pat, content) for pat in _VALIDATION_PATTERNS
    )
    if has_validation:
        return []

    return [MCPFinding(
        tool_name="(all tools)",
        file_path=fpath,
        line_number=tool_defs[0].start(),
        severity="high",
        category="missing_validation",
        message="MCP tools defined without visible input validation.",
        recommendation="Add input validation using Pydantic or manual checks.",
    )]


def _check_tool_permissions(
    fpath: str, content: str,
) -> list[MCPFinding]:
    """Check for overly broad tool permissions."""
    findings: list[MCPFinding] = []
    broad_patterns = (
        (r"glob\s*\(\s*['\"][*]{2}", "Recursive glob pattern may expose files"),
        (r"os\.walk\s*\(\s*['\"][/\\]", "Walking from root directory"),
        (r"Path\s*\(\s*['\"][/\\]", "Path starting from root directory"),
    )
    for pattern, message in broad_patterns:
        for match in re.finditer(pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(MCPFinding(
                tool_name=_extract_tool_name(content, match.start()),
                file_path=fpath,
                line_number=line_num,
                severity="medium",
                category="excessive_permissions",
                message=message,
                recommendation="Restrict paths to project-scoped directories.",
            ))
    return findings


def _check_mcp_config(repo_path: str) -> list[MCPFinding]:
    """Check MCP configuration files for security issues."""
    findings: list[MCPFinding] = []
    config_names = ("mcp.json", "mcp_config.json")

    for name in config_names:
        config_path = os.path.join(repo_path, name)
        if not os.path.isfile(config_path):
            continue
        try:
            with open(config_path, "r", encoding="utf-8") as fh:
                config = json.loads(fh.read())
        except (json.JSONDecodeError, OSError):
            continue

        servers = config.get("mcpServers", config.get("servers", {}))
        for server_name, server_cfg in servers.items():
            url = server_cfg.get("url", "")
            if url.startswith("http://") and "localhost" not in url:
                findings.append(MCPFinding(
                    tool_name=server_name,
                    file_path=config_path,
                    line_number=0,
                    severity="high",
                    category="insecure_transport",
                    message=f"MCP server '{server_name}' uses HTTP, not HTTPS.",
                    recommendation="Use HTTPS for remote MCP server connections.",
                ))

    return findings


def _extract_tool_name(content: str, position: int) -> str:
    """Extract the nearest function/tool name before a given position."""
    preceding = content[:position]
    match = re.search(r"def\s+(\w+)\s*\(", preceding[::-1])
    if match:
        return match.group(1)[::-1]

    match = re.search(r"(\w+)\s*=", preceding[-200:])
    if match:
        return match.group(1)

    return "unknown"


def _finding_to_dict(finding: MCPFinding) -> dict[str, Any]:
    """Convert an MCPFinding to a dictionary."""
    return {
        "tool_name": finding.tool_name,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "severity": finding.severity,
        "category": finding.category,
        "message": finding.message,
        "recommendation": finding.recommendation,
    }
