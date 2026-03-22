"""Scan lifecycle endpoints: create, status, progress stream, findings."""

import re
from typing import AsyncGenerator
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.db import finding_repo, scan_repo
from app.models.common import ErrorResponse, PaginatedResponse
from app.models.finding import Finding, FindingSummary
from app.models.scan import ScanCreate, ScanResponse, ScanStatus

router = APIRouter(prefix="/api/scans", tags=["scans"])

GITHUB_URL_PATTERN = re.compile(
    r"^https://github\.com/[\w.\-]+/[\w.\-]+/?$"
)


def _extract_repo_name(url: str) -> str:
    """Extract 'owner/repo' from a GitHub URL."""
    path = url.rstrip("/").removeprefix("https://github.com/")
    return path


@router.post(
    "",
    response_model=ScanResponse,
    status_code=201,
    responses={400: {"model": ErrorResponse}},
)
async def create_scan(body: ScanCreate) -> ScanResponse:
    """Validate a GitHub URL, persist the scan, and dispatch analysis."""
    url_str = str(body.repo_url).rstrip("/")

    if not GITHUB_URL_PATTERN.match(url_str):
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub repository URL. "
            "Expected format: https://github.com/owner/repo",
        )

    repo_name = _extract_repo_name(url_str)

    try:
        row = scan_repo.create_scan(
            repo_url=url_str,
            repo_name=repo_name,
            branch=body.branch,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create scan: {exc}",
        ) from exc

    # Dispatch Celery task (import deferred to avoid circular deps)
    try:
        from workers.scan_tasks import run_scan

        run_scan.delay(str(row["id"]))
    except Exception:
        # Task dispatch failure is non-fatal; scan stays queued.
        pass

    return ScanResponse(**row)


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    responses={404: {"model": ErrorResponse}},
)
async def get_scan(scan_id: UUID) -> ScanResponse:
    """Retrieve the current state of a scan."""
    row = scan_repo.get_scan(scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse(**row)


@router.get("/{scan_id}/progress")
async def scan_progress_stream(scan_id: UUID) -> StreamingResponse:
    """Server-Sent Events stream for real-time scan progress.

    This is a placeholder implementation that sends the current status
    once and closes.  A production version would subscribe to a Redis
    pub/sub channel or poll the database.
    """
    row = scan_repo.get_scan(scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def _event_generator() -> AsyncGenerator[str, None]:
        status = row.get("status", ScanStatus.QUEUED)
        progress = row.get("progress", 0)
        yield f"data: {{\"status\": \"{status}\", \"progress\": {progress}}}\n\n"

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


@router.get(
    "/{scan_id}/findings",
    response_model=PaginatedResponse[Finding],
    responses={404: {"model": ErrorResponse}},
)
async def list_findings(
    scan_id: UUID,
    severity: str | None = Query(None, description="Filter by severity"),
    category: str | None = Query(None, description="Filter by category"),
    agent_name: str | None = Query(None, description="Filter by agent"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
) -> PaginatedResponse[Finding]:
    """Return paginated findings for a scan with optional filters."""
    row = scan_repo.get_scan(scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings, total = finding_repo.get_findings_by_scan(
        scan_id,
        severity=severity,
        category=category,
        agent_name=agent_name,
        page=page,
        limit=limit,
    )

    return PaginatedResponse[Finding](
        data=[Finding(**f) for f in findings],
        total=total,
        page=page,
        limit=limit,
        has_next=(page * limit) < total,
    )


@router.get(
    "/{scan_id}/findings/summary",
    response_model=FindingSummary,
    responses={404: {"model": ErrorResponse}},
)
async def finding_summary(scan_id: UUID) -> FindingSummary:
    """Return aggregated finding counts by severity."""
    row = scan_repo.get_scan(scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return finding_repo.get_finding_summary(scan_id)
