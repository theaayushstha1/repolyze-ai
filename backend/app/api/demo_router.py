"""API routes for scans. Tries Celery for async processing,
falls back to asyncio in-process when Redis is not available."""

import asyncio
import logging
import re
import uuid
from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from app.demo_store import (
    add_findings, create_scan, get_findings, get_scan, update_scan,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scans", tags=["scans"])

GITHUB_URL_PATTERN = re.compile(r"^https://github\.com/[\w.\-]+/[\w.\-]+/?$")

# ── Celery availability check ──────────────────────────────────────────

_use_celery = False
try:
    import redis as _redis_mod
    from app.config import get_settings as _gs

    _r = _redis_mod.from_url(_gs().REDIS_URL, socket_connect_timeout=2)
    _r.ping()
    _r.close()
    _use_celery = True
    logger.info("Redis available, Celery dispatch enabled")
except Exception:
    logger.info("Redis not available, using asyncio fallback for scans")


def get_task_mode() -> str:
    """Return which task dispatch mode is active."""
    return "celery" if _use_celery else "asyncio"


# ── Asyncio fallback (same as before) ──────────────────────────────────

async def _run_scan_async(scan_id: str, repo_url: str) -> None:
    """Run scan pipeline in-process via asyncio + thread executor."""
    from app.services.scan_service import run_scan_pipeline

    update_scan(scan_id, status="cloning", progress=5, current_step="Cloning repository...")
    await asyncio.sleep(0.3)

    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, run_scan_pipeline, scan_id)
    except Exception as exc:
        logger.exception("Async scan failed for %s", repo_url)
        update_scan(scan_id, status="failed", error_message=str(exc))


# ── Endpoints ──────────────────────────────────────────────────────────

@router.post("", status_code=201)
async def create_scan_endpoint(body: dict) -> dict:
    url = str(body.get("repo_url", "")).rstrip("/")

    if not GITHUB_URL_PATTERN.match(url):
        raise HTTPException(status_code=400, detail="Invalid GitHub URL")

    repo_name = url.removeprefix("https://github.com/")
    scan = create_scan(repo_url=url, repo_name=repo_name, branch=body.get("branch", "main"))

    if _use_celery:
        try:
            from workers.scan_tasks import run_scan
            run_scan.delay(scan["id"])
            logger.info("Dispatched scan %s to Celery", scan["id"])
        except Exception:
            logger.warning("Celery dispatch failed, falling back to asyncio")
            asyncio.create_task(_run_scan_async(scan["id"], url))
    else:
        asyncio.create_task(_run_scan_async(scan["id"], url))

    return scan


@router.get("/{scan_id}")
async def get_scan_endpoint(scan_id: str) -> dict:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/progress")
async def scan_progress(scan_id: str) -> StreamingResponse:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def stream() -> AsyncGenerator[str, None]:
        while True:
            s = get_scan(scan_id)
            if s is None:
                break
            yield f"data: {{\"progress\": {s['progress']}, \"step\": \"{s.get('current_step', '')}\", \"status\": \"{s['status']}\"}}\n\n"
            if s["status"] in ("completed", "failed"):
                break
            await asyncio.sleep(2)

    return StreamingResponse(stream(), media_type="text/event-stream")


@router.get("/{scan_id}/findings")
async def get_findings_endpoint(scan_id: str) -> list[dict]:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return get_findings(scan_id)


@router.get("/{scan_id}/agent-findings")
async def get_agent_findings_endpoint(scan_id: str) -> list[dict]:
    findings = get_findings(scan_id)
    return [f for f in findings if f.get("agent_name") == "agent_safety"]


@router.post("/{scan_id}/reports")
async def generate_report(scan_id: str) -> dict:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Scan not yet completed")
    return {"id": "latest", "scan_id": scan_id, "status": "ready"}


@router.get("/{scan_id}/reports/{report_id}/download")
async def download_report(scan_id: str, report_id: str):
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
