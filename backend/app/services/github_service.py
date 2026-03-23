"""GitHub repository utilities: validation, cloning, language detection."""

import logging
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

logger = logging.getLogger(__name__)

GITHUB_URL_RE = re.compile(
    r"^https://github\.com/(?P<owner>[\w.\-]+)/(?P<repo>[\w.\-]+)/?$"
)

LANGUAGE_MAP: dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".jsx": "JavaScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".scala": "Scala",
    ".r": "R",
    ".dart": "Dart",
    ".lua": "Lua",
    ".sh": "Shell",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".json": "JSON",
    ".toml": "TOML",
}

AGENT_PATTERNS: dict[str, list[str]] = {
    "LangChain": ["from langchain", "from langgraph", "import langchain"],
    "CrewAI": ["from crewai", "import crewai"],
    "Google ADK": ["from google.adk", "from google import adk"],
    "OpenAI Agents": ["from openai.agents", "from agents import"],
    "AutoGen": ["from autogen", "import autogen"],
}

MCP_INDICATORS: list[str] = [
    "mcp.json",
    "mcpServers",
    "from mcp",
    "import mcp",
    "@mcp.tool",
]


def validate_github_url(url: str) -> bool:
    """Return True when *url* matches the expected GitHub repo pattern."""
    return GITHUB_URL_RE.match(url.strip()) is not None


def clone_repo(
    repo_url: str,
    *,
    branch: str = "main",
    target_dir: str | None = None,
) -> str:
    """Shallow-clone a GitHub repository and return the clone path.

    Args:
        repo_url: Full HTTPS GitHub URL.
        branch: Branch to clone.
        target_dir: Optional directory; a tempdir is created if omitted.

    Returns:
        Absolute path to the cloned repository.

    Raises:
        subprocess.CalledProcessError: If git clone fails.
    """
    dest = target_dir or tempfile.mkdtemp(prefix="repolyze_")
    cmd = [
        "git", "clone",
        "--depth", "1",
        "--branch", branch,
        repo_url,
        dest,
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    logger.info("Cloned %s (%s) to %s", repo_url, branch, dest)
    return dest


def detect_languages(repo_path: str) -> list[str]:
    """Count file extensions and return detected language names sorted by frequency."""
    counter: Counter[str] = Counter()

    for root, _dirs, files in os.walk(repo_path):
        if ".git" in root:
            continue
        for fname in files:
            ext = Path(fname).suffix.lower()
            lang = LANGUAGE_MAP.get(ext)
            if lang is not None:
                counter[lang] += 1

    return [lang for lang, _ in counter.most_common()]


def detect_agents(repo_path: str) -> list[str]:
    """Scan Python files for known AI agent framework imports."""
    detected: set[str] = set()

    for root, _dirs, files in os.walk(repo_path):
        if ".git" in root:
            continue
        for fname in files:
            if not fname.endswith(".py"):
                continue
            filepath = os.path.join(root, fname)
            try:
                content = Path(filepath).read_text(errors="ignore")
            except OSError:
                continue
            for framework, patterns in AGENT_PATTERNS.items():
                if any(p in content for p in patterns):
                    detected.add(framework)

    return sorted(detected)


def detect_mcp_servers(repo_path: str) -> list[str]:
    """Look for MCP configuration files or SDK imports."""
    hits: list[str] = []

    for root, _dirs, files in os.walk(repo_path):
        if ".git" in root:
            continue
        for fname in files:
            filepath = os.path.join(root, fname)
            if fname == "mcp.json":
                hits.append(filepath)
                continue
            if not fname.endswith((".py", ".ts", ".js", ".json")):
                continue
            try:
                content = Path(filepath).read_text(errors="ignore")
            except OSError:
                continue
            if any(indicator in content for indicator in MCP_INDICATORS):
                hits.append(filepath)

    return hits


def cleanup_repo(repo_path: str) -> None:
    """Remove a cloned repository directory."""
    try:
        shutil.rmtree(repo_path, ignore_errors=True)
        logger.info("Cleaned up %s", repo_path)
    except Exception:
        logger.warning("Failed to clean up %s", repo_path, exc_info=True)
