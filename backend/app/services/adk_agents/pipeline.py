"""ADK Pipeline Runner — executes the multi-agent security analysis.

This is the entry point called by real_scan_service.py. It:
1. Configures tools with scan context (repo path, findings, etc.)
2. Runs the orchestrator agent using InMemoryRunner
3. Parses agent responses back into our findings format
4. Returns enriched findings + AI summary
"""

import asyncio
import json
import logging
import os
import re
import uuid
from typing import Any

logger = logging.getLogger(__name__)

_API_KEY = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY", "")


def run_adk_pipeline(
    findings: list[dict[str, Any]],
    repo_path: str,
    languages: list[str],
    agents_detected: list[str],
) -> dict[str, Any]:
    """Run the ADK multi-agent pipeline and return enriched results.

    Args:
        findings: Raw findings from static scanners.
        repo_path: Path to cloned repository.
        languages: Detected programming languages.
        agents_detected: Detected AI agent frameworks.

    Returns:
        Dict with: new_findings (list), ai_summary (str), false_positives (list of indices)
    """
    if not _API_KEY or _API_KEY == "placeholder":
        logger.info("No API key configured, skipping ADK pipeline")
        return {"new_findings": [], "ai_summary": None, "false_positives": []}

    try:
        # Use a new event loop in a thread to avoid conflicts with uvicorn's loop
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                asyncio.run,
                _run_pipeline_async(findings, repo_path, languages, agents_detected),
            )
            return future.result(timeout=300)
    except Exception:
        logger.exception("ADK pipeline failed")
        return {"new_findings": [], "ai_summary": None, "false_positives": []}


async def _run_pipeline_async(
    findings: list[dict[str, Any]],
    repo_path: str,
    languages: list[str],
    agents_detected: list[str],
) -> dict[str, Any]:
    """Async execution of the agent pipeline."""
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    # Configure tools with scan context
    from app.services.adk_agents import tools
    tools.configure(repo_path, findings, languages, agents_detected)

    # Import agents
    from app.services.adk_agents.critic import critic_agent
    from app.services.adk_agents.researcher import researcher_agent
    from app.services.adk_agents.remediator import remediation_agent

    result = {
        "new_findings": [],
        "ai_summary": None,
        "false_positives": [],
        "remediations": [],
        "cve_context": [],
    }

    # Run each agent sequentially (like LLM Auditor pattern)
    # Each stage is wrapped in try/except so partial results survive

    # Stage 1: Critic verifies findings
    try:
        logger.info("ADK Stage 1: Running SecurityCritic agent")
        critic_response = await _run_single_agent(
            critic_agent,
            "Review the security scan findings. Call get_scan_context() first, "
            "then get_high_severity_findings(), then verify each by reading "
            "the source code. Provide your verdict as JSON.",
        )
        _parse_critic_response(critic_response, result)
        logger.info("ADK Stage 1 complete")
    except Exception:
        logger.exception("ADK Stage 1 (Critic) failed, continuing")

    # Stage 2: Researcher adds CVE context (google_search only, context via prompt)
    try:
        logger.info("ADK Stage 2: Running CVEResearcher agent")
        high_findings = [
            f for f in findings
            if f.get("severity") in ("CRITICAL", "HIGH")
        ][:10]
        findings_summary = "\n".join(
            f"- [{f.get('severity')}] {f.get('title')} (category: {f.get('category')}, "
            f"cve: {f.get('cve_id', 'none')})"
            for f in high_findings
        )
        researcher_prompt = (
            f"Here are the top security findings from a scan of a "
            f"{', '.join(languages)} repository"
            f"{' with ' + ', '.join(agents_detected) + ' agents' if agents_detected else ''}:\n\n"
            f"{findings_summary}\n\n"
            "Search for CVE details, security advisories, and known exploits "
            "for the most critical findings. Provide your research as JSON."
        )
        researcher_response = await _run_single_agent(researcher_agent, researcher_prompt)
        _parse_researcher_response(researcher_response, result)
        logger.info("ADK Stage 2 complete")
    except Exception:
        logger.exception("ADK Stage 2 (Researcher) failed, continuing")

    # Stage 3: Remediator generates fixes
    try:
        logger.info("ADK Stage 3: Running RemediationAdvisor agent")
        remediation_response = await _run_single_agent(
            remediation_agent,
            "Generate specific remediation advice for the security findings. "
            "Call get_scan_context() and get_high_severity_findings() first, "
            "then read the source code for each finding and provide specific "
            "code fixes. Provide your remediations as JSON.",
        )
        _parse_remediation_response(remediation_response, result)
        logger.info("ADK Stage 3 complete")
    except Exception:
        logger.exception("ADK Stage 3 (Remediator) failed, continuing")

    # Build executive summary from all stages
    result["ai_summary"] = _build_summary(result, findings)

    logger.info(
        "ADK pipeline complete: %d new findings, %d false positives, %d remediations",
        len(result["new_findings"]),
        len(result["false_positives"]),
        len(result["remediations"]),
    )

    return result


async def _run_single_agent(agent, prompt: str) -> str:
    """Run a single ADK agent and collect its final response."""
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    runner = InMemoryRunner(agent=agent, app_name="repolyze")
    session = await runner.session_service.create_session(
        app_name="repolyze", user_id="scanner",
    )

    content = types.Content(
        role="user",
        parts=[types.Part(text=prompt)],
    )

    final_text = ""
    all_text = ""
    try:
        async for event in runner.run_async(
            user_id="scanner",
            session_id=session.id,
            new_message=content,
        ):
            if event.content and event.content.parts:
                for part in event.content.parts:
                    if hasattr(part, "text") and part.text:
                        all_text += part.text
            if event.is_final_response() and event.content and event.content.parts:
                for part in event.content.parts:
                    if hasattr(part, "text") and part.text:
                        final_text += part.text
    finally:
        await runner.close()

    # Use final response if available, otherwise use all collected text
    result = final_text or all_text
    if result:
        logger.info("Agent %s response length: %d chars", agent.name, len(result))
        logger.debug("Agent %s response preview: %s", agent.name, result[:500])
    else:
        logger.warning("Agent %s returned empty response", agent.name)

    return result


def _extract_json(text: str) -> dict | list | None:
    """Extract JSON from agent response text, handling markdown fences."""
    if not text:
        return None

    # Try to find JSON in markdown code fences
    fence_match = re.search(r"```(?:json)?\s*\n?([\s\S]*?)\n?```", text)
    if fence_match:
        text = fence_match.group(1).strip()

    # Try to find JSON object or array
    for start_char, end_char in [("{", "}"), ("[", "]")]:
        start = text.find(start_char)
        if start == -1:
            continue
        # Find matching closing brace/bracket
        depth = 0
        for i in range(start, len(text)):
            if text[i] == start_char:
                depth += 1
            elif text[i] == end_char:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i+1])
                    except json.JSONDecodeError:
                        break

    return None


def _parse_critic_response(response: str, result: dict) -> None:
    """Parse CriticAgent response into result dict."""
    data = _extract_json(response)
    if not data or not isinstance(data, dict):
        logger.warning("Could not parse critic response as JSON")
        return

    # Extract false positive indices
    for vf in data.get("verified_findings", []):
        if vf.get("verdict") == "FALSE_POSITIVE":
            idx = vf.get("index")
            if isinstance(idx, int):
                result["false_positives"].append(idx)

    # Extract new findings from critic
    for nf in data.get("new_findings", []):
        if not isinstance(nf, dict) or not nf.get("title"):
            continue
        result["new_findings"].append({
            "id": str(uuid.uuid4()),
            "scan_id": None,
            "agent_name": "ai_review",
            "tool_name": "adk_critic",
            "category": nf.get("category", "ai_review"),
            "severity": nf.get("severity", "MEDIUM").upper(),
            "confidence": "medium",
            "title": nf["title"],
            "description": nf.get("description", ""),
            "file_path": nf.get("file_path", ""),
            "line_start": nf.get("line_start"),
            "line_end": None,
            "code_snippet": None,
            "cwe_id": nf.get("cwe_id"),
            "cve_id": None,
            "remediation": nf.get("remediation", ""),
        })

    logger.info(
        "Critic: %d false positives, %d new findings",
        len(result["false_positives"]),
        len([f for f in data.get("new_findings", [])]),
    )


def _parse_researcher_response(response: str, result: dict) -> None:
    """Parse ResearcherAgent response into result dict."""
    data = _extract_json(response)
    if not data or not isinstance(data, dict):
        logger.warning("Could not parse researcher response as JSON")
        return

    result["cve_context"] = data.get("cve_context", [])
    logger.info("Researcher: %d CVE contexts found", len(result["cve_context"]))


def _parse_remediation_response(response: str, result: dict) -> None:
    """Parse RemediationAgent response into result dict."""
    data = _extract_json(response)
    if not data or not isinstance(data, dict):
        logger.warning("Could not parse remediation response as JSON")
        return

    result["remediations"] = data.get("remediations", [])
    result["quick_wins"] = data.get("quick_wins", [])
    logger.info("Remediator: %d fixes generated", len(result["remediations"]))


def _build_summary(result: dict, original_findings: list) -> str:
    """Build a concise executive summary from all agent outputs."""
    parts = []

    total = len(original_findings)
    fps = len(result["false_positives"])
    new = len(result["new_findings"])
    fixes = len(result["remediations"])

    parts.append(
        f"AI-powered analysis reviewed {total} findings from static scanners. "
        f"{fps} were identified as false positives. "
        f"{new} additional vulnerabilities were discovered through code analysis."
    )

    if result.get("quick_wins"):
        parts.append("Quick wins: " + "; ".join(result["quick_wins"][:3]) + ".")

    if fixes:
        parts.append(f"{fixes} specific code fixes have been generated.")

    return " ".join(parts)
