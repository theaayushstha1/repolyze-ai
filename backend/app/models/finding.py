"""Pydantic models for security findings."""

from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    """A single security or quality finding."""

    model_config = {"frozen": True}

    id: UUID
    scan_id: UUID
    agent_name: str
    tool_name: str
    category: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    description: str
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    code_snippet: str | None = None
    cwe_id: str | None = None
    cve_id: str | None = None
    remediation: str | None = None


class AgentFinding(Finding):
    """Extended finding produced by an AI agent probe."""

    test_type: str
    prompt_used: str | None = None
    response: str | None = None
    pass_fail: str | None = None
    risk_level: str | None = None


class FindingSummary(BaseModel):
    """Aggregated counts by severity."""

    model_config = {"frozen": True}

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
