"""Pydantic models for scan requests and responses."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field, HttpUrl


class ScanStatus(StrEnum):
    """Lifecycle states of a repository scan."""

    QUEUED = "queued"
    CLONING = "cloning"
    ANALYZING = "analyzing"
    GENERATING_REPORT = "generating_report"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanCreate(BaseModel):
    """Payload for creating a new scan."""

    model_config = {"frozen": True}

    repo_url: HttpUrl
    branch: str = Field(default="main", min_length=1, max_length=256)


class ScanResponse(BaseModel):
    """Full scan record returned to callers."""

    model_config = {"frozen": True}

    id: UUID
    repo_url: str
    repo_name: str
    status: ScanStatus
    progress: int = Field(ge=0, le=100, default=0)
    languages_detected: list[str] = Field(default_factory=list)
    findings_total: int = 0
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    findings_info: int = 0
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None
    error_message: str | None = None
