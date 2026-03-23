"""Gemini AI-powered code review for contextual vulnerability analysis.

Takes findings from static scanners and uses Gemini to:
1. Verify if findings are real vulnerabilities (reduce false positives)
2. Assess business impact and exploitability
3. Generate contextual remediation advice
4. Find patterns the regex scanners missed
"""

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Load API key from env
_API_KEY = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY", "")


def _get_client():
    """Lazy-load the Gemini client."""
    from google import genai
    return genai.Client(api_key=_API_KEY)


def ai_review_findings(
    findings: list[dict[str, Any]],
    repo_path: str,
    languages: list[str],
    agents_detected: list[str],
) -> list[dict[str, Any]]:
    """Use Gemini to review and enrich scanner findings.

    Args:
        findings: Raw findings from static scanners.
        repo_path: Path to cloned repo for reading source context.
        languages: Detected programming languages.
        agents_detected: Detected AI agent frameworks.

    Returns:
        Enriched findings with AI analysis added.
    """
    if not _API_KEY or _API_KEY == "placeholder":
        logger.info("No Gemini API key, skipping AI review")
        return findings

    try:
        client = _get_client()
    except Exception:
        logger.warning("Failed to init Gemini client, skipping AI review")
        return findings

    # Group high-severity findings for review (don't waste tokens on LOW/INFO)
    high_priority = [
        f for f in findings
        if f.get("severity") in ("CRITICAL", "HIGH")
    ]

    if not high_priority:
        return findings

    # Take top 20 to avoid token limits
    to_review = high_priority[:20]

    # Build context with actual source code
    review_context = _build_review_context(to_review, repo_path)

    try:
        ai_findings = _run_gemini_review(client, review_context, languages, agents_detected)
        findings.extend(ai_findings)
    except Exception:
        logger.exception("Gemini review failed, continuing with static findings")

    return findings


def _build_review_context(
    findings: list[dict[str, Any]],
    repo_path: str,
) -> list[dict[str, Any]]:
    """Build context objects with source code for each finding."""
    contexts = []

    for f in findings:
        file_path = f.get("file_path", "")
        if not file_path:
            continue

        # Read source file for context
        full_path = os.path.join(repo_path, file_path)
        source_snippet = ""
        try:
            content = Path(full_path).read_text(errors="ignore")
            lines = content.splitlines()
            line_start = max(0, (f.get("line_start") or 1) - 5)
            line_end = min(len(lines), (f.get("line_end") or f.get("line_start") or 1) + 10)
            source_snippet = "\n".join(
                f"{i+1}: {line}" for i, line in enumerate(lines[line_start:line_end], start=line_start)
            )
        except (OSError, TypeError):
            pass

        contexts.append({
            "title": f.get("title", ""),
            "category": f.get("category", ""),
            "severity": f.get("severity", ""),
            "file_path": file_path,
            "line_start": f.get("line_start"),
            "description": f.get("description", ""),
            "source_code": source_snippet[:2000],  # Cap at 2K chars
        })

    return contexts


def _run_gemini_review(
    client,
    contexts: list[dict[str, Any]],
    languages: list[str],
    agents_detected: list[str],
) -> list[dict[str, Any]]:
    """Call Gemini to analyze findings and return AI-generated insights."""
    if not contexts:
        return []

    # Build the prompt
    findings_text = json.dumps(contexts[:15], indent=2)  # Limit for token budget

    prompt = f"""You are a senior security auditor reviewing code findings from static analysis tools.

## Repository Context
- Languages: {', '.join(languages)}
- AI Agent Frameworks Detected: {', '.join(agents_detected) if agents_detected else 'None'}

## Findings to Review
{findings_text}

## Your Task
Analyze these findings and provide:

1. **False Positive Check**: Which findings look like false positives? Mark them.
2. **Missing Vulnerabilities**: Based on the code patterns you see, identify 2-3 additional vulnerabilities the static scanners may have missed. Focus on:
   - Business logic flaws (race conditions, TOCTOU, authorization bypasses)
   - Insecure design patterns (IDOR, privilege escalation paths)
   - AI agent specific risks (prompt injection vectors, tool misuse paths)
   - Data flow issues (sensitive data exposure, improper validation chains)
3. **Severity Assessment**: For each new finding, rate CRITICAL/HIGH/MEDIUM/LOW.

## Response Format
Return ONLY a JSON array of new findings (not the existing ones). Each finding must have:
{{"title": "...", "category": "ai_review", "severity": "HIGH", "description": "...", "file_path": "...", "line_start": null, "remediation": "..."}}

If you find nothing new, return an empty array: []
Return ONLY valid JSON, no markdown fences or extra text."""

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
    )

    raw_text = response.text.strip()

    # Parse JSON from response (handle markdown fences)
    if raw_text.startswith("```"):
        raw_text = raw_text.split("```")[1]
        if raw_text.startswith("json"):
            raw_text = raw_text[4:]
    raw_text = raw_text.strip()

    try:
        new_findings = json.loads(raw_text)
    except json.JSONDecodeError:
        logger.warning("Failed to parse Gemini response as JSON")
        return []

    if not isinstance(new_findings, list):
        return []

    # Normalize findings to match our schema
    normalized = []
    for f in new_findings:
        if not isinstance(f, dict) or not f.get("title"):
            continue
        normalized.append({
            "scan_id": None,
            "agent_name": "ai_review",
            "tool_name": "gemini-2.5-flash",
            "category": f.get("category", "ai_review"),
            "severity": f.get("severity", "MEDIUM").upper(),
            "confidence": "medium",
            "title": f["title"],
            "description": f.get("description", ""),
            "file_path": f.get("file_path", ""),
            "line_start": f.get("line_start"),
            "line_end": None,
            "code_snippet": None,
            "cwe_id": f.get("cwe_id"),
            "cve_id": None,
            "remediation": f.get("remediation", ""),
        })

    logger.info("Gemini AI review found %d additional findings", len(normalized))
    return normalized


def ai_summarize_scan(
    findings: list[dict[str, Any]],
    languages: list[str],
    agents_detected: list[str],
    grade: str,
) -> str | None:
    """Generate a natural-language executive summary of scan results."""
    if not _API_KEY or _API_KEY == "placeholder":
        return None

    try:
        client = _get_client()
    except Exception:
        return None

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    categories = {}
    for f in findings:
        cat = f.get("category", "other")
        categories[cat] = categories.get(cat, 0) + 1

    prompt = f"""Write a 3-4 sentence executive summary for a security audit report.

Repository scanned with these results:
- Languages: {', '.join(languages)}
- AI Agents Detected: {', '.join(agents_detected) if agents_detected else 'None'}
- Agent Safety Grade: {grade}
- Total Findings: {len(findings)}
- By Severity: {json.dumps(severity_counts)}
- By Category: {json.dumps(dict(list(categories.items())[:10]))}

Write in a professional but direct tone. Mention the most critical risks first. Keep it under 100 words. No bullet points, just prose."""

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        return response.text.strip()
    except Exception:
        logger.exception("Failed to generate AI summary")
        return None
