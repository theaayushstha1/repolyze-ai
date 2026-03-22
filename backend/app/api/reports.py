"""Report generation and download endpoints."""

from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.db import scan_repo
from app.models.common import ErrorResponse
from app.models.report import ReportResponse

router = APIRouter(prefix="/api/scans", tags=["reports"])


@router.post(
    "/{scan_id}/reports",
    response_model=ReportResponse,
    status_code=202,
    responses={404: {"model": ErrorResponse}},
)
async def generate_report(scan_id: UUID) -> ReportResponse:
    """Queue PDF report generation for a completed scan."""
    row = scan_repo.get_scan(scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if row.get("status") != "completed":
        raise HTTPException(
            status_code=400,
            detail="Report can only be generated for completed scans",
        )

    # Placeholder: In production this would dispatch a Celery task and
    # persist a report record in the database.
    from datetime import datetime, timezone

    report_id = uuid4()
    return ReportResponse(
        id=report_id,
        scan_id=scan_id,
        status="queued",
        format="pdf",
        download_url=None,
        created_at=datetime.now(timezone.utc),
        completed_at=None,
    )


@router.get(
    "/{scan_id}/reports/{report_id}/download",
    responses={404: {"model": ErrorResponse}},
)
async def download_report(scan_id: UUID, report_id: UUID) -> FileResponse:
    """Download a generated PDF report.

    Placeholder: returns 404 until report generation is implemented.
    """
    raise HTTPException(
        status_code=404,
        detail="Report not found or not yet generated",
    )
