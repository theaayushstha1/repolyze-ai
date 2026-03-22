"""Pydantic models for report generation and retrieval."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class ReportResponse(BaseModel):
    """Metadata for a generated PDF report."""

    model_config = {"frozen": True}

    id: UUID
    scan_id: UUID
    status: str
    format: str = "pdf"
    download_url: str | None = None
    created_at: datetime
    completed_at: datetime | None = None
