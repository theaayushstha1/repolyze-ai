"""Auto-detect agent frameworks present in a repository.

Scans for import patterns, configuration files, and directory structures
that indicate usage of LangChain, CrewAI, Google ADK, OpenAI Agents SDK,
and MCP servers.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FrameworkDetection:
    """Immutable result of a framework detection check."""

    detected: bool
    framework: str
    files: tuple[str, ...]
    confidence: float  # 0.0 - 1.0


# -- Import patterns ---------------------------------------------------------

_LANGCHAIN_PATTERNS: tuple[str, ...] = (
    r"from\s+langchain",
    r"import\s+langchain",
    r"from\s+langgraph",
    r"import\s+langgraph",
)

_CREWAI_PATTERNS: tuple[str, ...] = (
    r"from\s+crewai",
    r"import\s+crewai",
)

_ADK_PATTERNS: tuple[str, ...] = (
    r"from\s+google\.adk",
    r"import\s+google\.adk",
)

_OPENAI_AGENTS_PATTERNS: tuple[str, ...] = (
    r"from\s+openai\.agents",
    r"from\s+agents\s+import",
    r"openai\.agents\.Agent",
)

_MCP_PATTERNS: tuple[str, ...] = (
    r"from\s+mcp",
    r"import\s+mcp",
    r"@mcp\.tool",
    r"McpServer",
    r"mcp_server",
)


# -- Helpers ------------------------------------------------------------------

def _scan_files_for_patterns(
    repo_path: str,
    patterns: tuple[str, ...],
) -> tuple[str, ...]:
    """Walk Python files and return those matching any pattern."""
    matched: list[str] = []
    compiled = tuple(re.compile(p) for p in patterns)

    for root, _dirs, files in os.walk(repo_path):
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            try:
                content = _read_file_safe(fpath)
            except OSError:
                continue
            if any(rx.search(content) for rx in compiled):
                matched.append(fpath)

    return tuple(matched)


def _read_file_safe(path: str, max_bytes: int = 256_000) -> str:
    """Read a file safely with a size limit."""
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return fh.read(max_bytes)


def _check_config_files(
    repo_path: str,
    filenames: tuple[str, ...],
) -> tuple[str, ...]:
    """Check for configuration files in the repo root."""
    found: list[str] = []
    for name in filenames:
        candidate = os.path.join(repo_path, name)
        if os.path.isfile(candidate):
            found.append(candidate)
    return tuple(found)


# -- Public detectors ---------------------------------------------------------

def detect_langchain(repo_path: str) -> FrameworkDetection:
    """Detect LangChain / LangGraph usage."""
    files = _scan_files_for_patterns(repo_path, _LANGCHAIN_PATTERNS)
    return FrameworkDetection(
        detected=len(files) > 0,
        framework="langchain",
        files=files,
        confidence=min(1.0, len(files) * 0.3),
    )


def detect_crewai(repo_path: str) -> FrameworkDetection:
    """Detect CrewAI usage."""
    files = _scan_files_for_patterns(repo_path, _CREWAI_PATTERNS)
    return FrameworkDetection(
        detected=len(files) > 0,
        framework="crewai",
        files=files,
        confidence=min(1.0, len(files) * 0.3),
    )


def detect_adk(repo_path: str) -> FrameworkDetection:
    """Detect Google ADK usage."""
    files = _scan_files_for_patterns(repo_path, _ADK_PATTERNS)
    return FrameworkDetection(
        detected=len(files) > 0,
        framework="adk",
        files=files,
        confidence=min(1.0, len(files) * 0.3),
    )


def detect_openai_agents(repo_path: str) -> FrameworkDetection:
    """Detect OpenAI Agents SDK usage."""
    files = _scan_files_for_patterns(repo_path, _OPENAI_AGENTS_PATTERNS)
    return FrameworkDetection(
        detected=len(files) > 0,
        framework="openai_agents",
        files=files,
        confidence=min(1.0, len(files) * 0.3),
    )


def detect_mcp_servers(repo_path: str) -> FrameworkDetection:
    """Detect MCP server implementations."""
    files = _scan_files_for_patterns(repo_path, _MCP_PATTERNS)
    config_files = _check_config_files(
        repo_path, ("mcp.json", "mcp_config.json", "claude_desktop_config.json")
    )
    all_files = files + config_files
    return FrameworkDetection(
        detected=len(all_files) > 0,
        framework="mcp",
        files=all_files,
        confidence=min(1.0, len(all_files) * 0.3),
    )


def detect_all(repo_path: str) -> dict[str, Any]:
    """Detect all supported agent frameworks in the repository.

    Returns:
        Dictionary keyed by framework name with detection results.
    """
    detectors = {
        "langchain": detect_langchain,
        "crewai": detect_crewai,
        "adk": detect_adk,
        "openai_agents": detect_openai_agents,
        "mcp": detect_mcp_servers,
    }
    results: dict[str, Any] = {}
    for name, detector_fn in detectors.items():
        detection = detector_fn(repo_path)
        results[name] = {
            "detected": detection.detected,
            "files": list(detection.files),
            "confidence": detection.confidence,
        }
    return results
