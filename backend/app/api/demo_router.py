"""Demo-mode API that works without Supabase/Redis.
Uses in-memory store. Runs REAL scanners (Semgrep, agent safety, MCP audit)
when available, falls back to simulated data."""

import asyncio
import logging
import random
import re
import uuid
from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException, Query

logger = logging.getLogger(__name__)
from fastapi.responses import StreamingResponse

from app.demo_store import add_findings, create_scan, get_findings, get_scan, update_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])

GITHUB_URL_PATTERN = re.compile(r"^https://github\.com/[\w.\-]+/[\w.\-]+/?$")

DEMO_FINDINGS = [
    {"severity": "CRITICAL", "category": "injection", "title": "SQL Injection in query builder", "description": "User input concatenated directly into SQL query without parameterization", "file_path": "src/db/queries.py", "line_start": 45, "cwe_id": "CWE-89", "tool_name": "semgrep", "agent_name": "static_analysis", "remediation": "Use parameterized queries or an ORM"},
    {"severity": "HIGH", "category": "secret_leak", "title": "Hardcoded API key detected", "description": "AWS access key found in source code", "file_path": "config/settings.py", "line_start": 12, "cwe_id": "CWE-798", "tool_name": "trufflehog", "agent_name": "secret_detection", "remediation": "Move secrets to environment variables or a secret manager"},
    {"severity": "HIGH", "category": "agent_safety", "title": "Missing input guardrails on LangChain agent", "description": "Agent accepts raw user input without validation or content filtering", "file_path": "agents/chat_agent.py", "line_start": 34, "cwe_id": None, "tool_name": "agent_safety_static", "agent_name": "agent_safety", "remediation": "Add input validation and content safety guardrails before passing to LLM"},
    {"severity": "MEDIUM", "category": "xss", "title": "Reflected XSS in search endpoint", "description": "User search query reflected in HTML response without escaping", "file_path": "src/routes/search.py", "line_start": 78, "cwe_id": "CWE-79", "tool_name": "semgrep", "agent_name": "static_analysis", "remediation": "Escape output or use a template engine with auto-escaping"},
    {"severity": "MEDIUM", "category": "vulnerable_dependency", "title": "requests 2.25.1 has known CVE", "description": "CVE-2023-32681: Unintended leak of Proxy-Authorization header", "file_path": "requirements.txt", "line_start": 5, "cve_id": "CVE-2023-32681", "cwe_id": None, "tool_name": "osv-scanner", "agent_name": "dependency_audit", "remediation": "Upgrade to requests >= 2.31.0"},
    {"severity": "MEDIUM", "category": "agent_safety", "title": "System prompt exposed in error handler", "description": "Full system prompt returned in API error response when LLM fails", "file_path": "agents/chat_agent.py", "line_start": 89, "cwe_id": None, "tool_name": "agent_safety_static", "agent_name": "agent_safety", "remediation": "Return generic error messages; never expose system prompts"},
    {"severity": "LOW", "category": "mcp_security", "title": "MCP tool lacks input validation", "description": "The 'file_read' tool accepts arbitrary paths without sanitization", "file_path": "mcp_server/tools.py", "line_start": 23, "cwe_id": "CWE-22", "tool_name": "mcp_auditor", "agent_name": "mcp_auditor", "remediation": "Validate and sanitize file paths; restrict to allowed directories"},
    {"severity": "LOW", "category": "security_misconfig", "title": "Debug mode enabled in production config", "description": "DEBUG=True found in production configuration file", "file_path": "config/production.py", "line_start": 3, "cwe_id": "CWE-489", "tool_name": "semgrep", "agent_name": "static_analysis", "remediation": "Set DEBUG=False in production"},
    {"severity": "INFO", "category": "license", "title": "GPL-3.0 dependency in MIT project", "description": "Dependency 'some-lib' uses GPL-3.0 which is incompatible with MIT license", "file_path": "package.json", "line_start": 15, "cwe_id": None, "tool_name": "license_checker", "agent_name": "license_compliance", "remediation": "Replace with a permissively licensed alternative"},
]

SCAN_STEPS = [
    (10, "Cloning repository..."),
    (20, "Detecting languages..."),
    (30, "Detecting AI agents and MCP servers..."),
    (45, "Running Semgrep static analysis..."),
    (55, "Scanning dependencies for CVEs..."),
    (65, "Detecting leaked secrets..."),
    (75, "Auditing AI agent safety..."),
    (85, "Auditing MCP server configuration..."),
    (95, "Generating report..."),
    (100, "Scan complete!"),
]


async def _run_real_scan(scan_id: str, repo_url: str) -> None:
    """Run REAL scan pipeline in background: clone → detect → scan → aggregate."""
    from app.services.real_scan_service import run_full_scan

    update_scan(scan_id, status="cloning", progress=5, current_step="Cloning repository...")
    await asyncio.sleep(0.5)  # Let frontend pick up status

    update_scan(scan_id, progress=10, current_step="Cloning repository...")

    # Run the blocking scan in a thread pool to avoid blocking the event loop
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, run_full_scan, repo_url)
    except Exception as exc:
        logger.exception("Real scan failed for %s", repo_url)
        update_scan(scan_id, status="failed", error_message=str(exc))
        return

    if result.get("status") == "failed":
        update_scan(
            scan_id, status="failed",
            error_message=result.get("error_message", "Unknown error"),
        )
        return

    # Update progress through stages
    update_scan(scan_id, progress=30, current_step="Detecting languages and frameworks...", status="analyzing")
    await asyncio.sleep(0.3)

    update_scan(
        scan_id, progress=50,
        current_step="Running security analysis...",
        languages_detected=result.get("languages_detected"),
        agents_detected=result.get("agents_detected"),
        mcp_detected=result.get("mcp_detected", False),
    )
    await asyncio.sleep(0.3)

    # Store findings
    findings = result.get("findings", [])
    for f in findings:
        f["id"] = f.get("id") or str(uuid.uuid4())
        f["scan_id"] = scan_id
    add_findings(scan_id, findings)

    update_scan(scan_id, progress=90, current_step="Aggregating results...")
    await asyncio.sleep(0.3)

    # Final update
    update_scan(
        scan_id,
        status="completed",
        progress=100,
        current_step="Scan complete!",
        total_findings=result.get("total_findings", 0),
        critical_count=result.get("critical_count", 0),
        high_count=result.get("high_count", 0),
        medium_count=result.get("medium_count", 0),
        low_count=result.get("low_count", 0),
        info_count=result.get("info_count", 0),
        agent_safety_grade=result.get("agent_safety_grade"),
        scan_duration_ms=result.get("scan_duration_ms"),
        completed_at=__import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
    )
    logger.info(
        "Scan %s complete: %d findings, grade=%s",
        scan_id, len(findings), result.get("agent_safety_grade"),
    )


@router.post("", status_code=201)
async def demo_create_scan(body: dict) -> dict:
    url = str(body.get("repo_url", "")).rstrip("/")

    if not GITHUB_URL_PATTERN.match(url):
        raise HTTPException(status_code=400, detail="Invalid GitHub URL")

    repo_name = url.removeprefix("https://github.com/")
    scan = create_scan(repo_url=url, repo_name=repo_name, branch=body.get("branch", "main"))

    # Start real scan in background
    asyncio.create_task(_run_real_scan(scan["id"], url))

    return scan


@router.get("/{scan_id}")
async def demo_get_scan(scan_id: str) -> dict:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/progress")
async def demo_progress(scan_id: str) -> StreamingResponse:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def stream() -> AsyncGenerator[str, None]:
        while True:
            s = get_scan(scan_id)
            if s is None:
                break
            yield f"data: {{\"progress\": {s['progress']}, \"step\": \"{s['current_step']}\", \"status\": \"{s['status']}\"}}\n\n"
            if s["status"] in ("completed", "failed"):
                break
            await asyncio.sleep(2)

    return StreamingResponse(stream(), media_type="text/event-stream")


@router.get("/{scan_id}/findings")
async def demo_findings(scan_id: str) -> list[dict]:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return get_findings(scan_id)


@router.get("/{scan_id}/agent-findings")
async def demo_agent_findings(scan_id: str) -> list[dict]:
    findings = get_findings(scan_id)
    return [f for f in findings if f.get("agent_name") == "agent_safety"]


@router.post("/{scan_id}/reports")
async def demo_generate_report(scan_id: str) -> dict:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Scan not yet completed")
    return {"id": "latest", "scan_id": scan_id, "status": "ready"}


@router.get("/{scan_id}/reports/{report_id}/download")
async def demo_download_report(scan_id: str, report_id: str):
    from fastapi.responses import Response
    from app.services.pdf_generator import generate_report_pdf

    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Scan not yet completed")

    findings = get_findings(scan_id)
    pdf_bytes = generate_report_pdf(scan, findings)

    repo_name = scan.get("repo_name", "report").replace("/", "_")
    filename = f"RepolyzeAI_Audit_{repo_name}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
