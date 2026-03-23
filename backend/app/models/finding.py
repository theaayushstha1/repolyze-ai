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
    tool_name: str | None = None
    category: str
    severity: Severity
    confidence: str = "medium"
    title: str
    description: str
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    code_snippet: str | None = None
    cwe_id: str | None = None
    cve_id: str | None = None
    remediation: str | None = None


class AgentFinding(BaseModel):
    """AI agent safety finding from red-team or static analysis."""

    model_config = {"frozen": True}

    id: UUID
    scan_id: UUID
    agent_name: str
    test_type: str
    category: str
    severity: Severity
    title: str
    description: str
    prompt_used: str | None = None
    response: str | None = None
    pass_fail: str = "fail"
    risk_level: str = "medium"
    owasp_category: str | None = None
    remediation: str | None = None


class FindingSummary(BaseModel):
    """Aggregated counts by severity."""

    model_config = {"frozen": True}

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
