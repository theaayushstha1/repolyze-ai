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
    """Full scan record returned to callers.

    Field names match the DB schema and demo_store exactly.
    """

    model_config = {"frozen": True}

    id: UUID
    repo_url: str
    repo_name: str
    branch: str = "main"
    commit_sha: str | None = None
    status: ScanStatus
    progress: int = Field(ge=0, le=100, default=0)
    current_step: str | None = None
    languages_detected: list[str] | None = None
    agents_detected: list[str] | None = None
    mcp_detected: bool = False
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    agent_safety_grade: str | None = None
    scan_duration_ms: int | None = None
    error_message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
