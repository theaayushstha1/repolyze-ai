"""SecurityOrchestrator — root agent that dispatches to sub-agents.

Uses Google ADK LlmAgent pattern. Detects repository languages and agent
frameworks, then fans out to the appropriate sub-agents and aggregates their
results into a unified security report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from google.adk.agents import LlmAgent

from agents.agent_safety.detector import detect_all
from agents.static_analysis.agent import static_analysis_agent
from agents.dependency_audit.agent import dependency_audit_agent
from agents.secret_detection.agent import secret_detection_agent
from agents.agent_safety.red_team.orchestrator import red_team_orchestrator
from agents.mcp_auditor.agent import mcp_auditor_agent
from agents.ai_review.agent import ai_review_agent
from agents.license_compliance.agent import license_compliance_agent


MODEL = "gemini-2.5-flash"


@dataclass(frozen=True)
class ScanRequest:
    """Immutable scan request."""

    repo_path: str
    languages: tuple[str, ...] = ()
    scan_id: str = ""


@dataclass(frozen=True)
class AggregatedReport:
    """Immutable aggregated report from all sub-agents."""

    scan_id: str
    findings: tuple[dict[str, Any], ...] = ()
    agent_safety_results: dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    risk_score: float = 0.0


def _detect_languages(repo_path: str) -> tuple[str, ...]:
    """Detect programming languages present in the repository."""
    import os

    extension_map: dict[str, str] = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".go": "go",
        ".rs": "rust",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".cpp": "cpp",
    }
    detected: set[str] = set()
    for root, _dirs, files in os.walk(repo_path):
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in extension_map:
                detected.add(extension_map[ext])
    return tuple(sorted(detected))


def _build_sub_agents(
    languages: tuple[str, ...],
    frameworks: dict[str, Any],
) -> list[LlmAgent]:
    """Build the list of sub-agents to dispatch based on context."""
    agents: list[LlmAgent] = [
        static_analysis_agent,
        dependency_audit_agent,
        secret_detection_agent,
        ai_review_agent,
        license_compliance_agent,
    ]

    has_agent_framework = any(
        frameworks.get(fw, {}).get("detected", False)
        for fw in frameworks
    )
    if has_agent_framework:
        agents.append(mcp_auditor_agent)

    return agents


def build_orchestrator(repo_path: str, scan_id: str = "") -> LlmAgent:
    """Build the root orchestrator agent for a given repository."""
    languages = _detect_languages(repo_path)
    frameworks = detect_all(repo_path)

    sub_agents = _build_sub_agents(languages, frameworks)

    orchestrator = LlmAgent(
        name="SecurityOrchestrator",
        model=MODEL,
        instruction=(
            "You are a security orchestrator. Coordinate the sub-agents to "
            "perform a comprehensive security scan of the repository. "
            "Aggregate all findings and produce a unified risk assessment.\n\n"
            f"Repository: {repo_path}\n"
            f"Languages detected: {', '.join(languages)}\n"
            f"Agent frameworks detected: "
            f"{', '.join(k for k, v in frameworks.items() if v.get('detected'))}\n"
            f"Scan ID: {scan_id}"
        ),
        sub_agents=sub_agents,
    )
    return orchestrator
