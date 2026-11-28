from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from app.models.incident import IncidentStatus


class IncidentBase(BaseModel):
    repository: str
    commit_sha: str
    author: Optional[str] = "unknown"
    detector_name: str
    secret_masked: str
    file_path: str
    line_number: Optional[int] = 1
    severity: Optional[str] = "CRITICAL"
    status: Optional[str] = IncidentStatus.DETECTED.value
    remediation_status: Optional[str] = "pending"
    remediation_notes: Optional[str] = None
    vault_secret_path: Optional[str] = None
    secret_fingerprint: Optional[str] = None
    secret_category: Optional[str] = "generic_secret"
    risk_score: Optional[float] = 75.0
    risk_factors: Optional[str] = None
    correlation_group_id: Optional[str] = None
    occurrence_count: Optional[int] = 1
    is_false_positive: Optional[bool] = False
    false_positive_reason: Optional[str] = None


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    remediation_status: Optional[str] = None
    remediation_notes: Optional[str] = None
    vault_secret_path: Optional[str] = None
    secret_fingerprint: Optional[str] = None
    secret_category: Optional[str] = "generic_secret"
    risk_score: Optional[float] = 75.0
    risk_factors: Optional[str] = None
    correlation_group_id: Optional[str] = None
    occurrence_count: Optional[int] = 1
    is_false_positive: Optional[bool] = False
    false_positive_reason: Optional[str] = None


class IncidentResponse(IncidentBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: str
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class IncidentListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    incidents: List[IncidentResponse]


class IncidentStats(BaseModel):
    total_incidents: int
    critical_incidents: int
    resolved_incidents: int
    pending_rotations: int
    by_severity: dict
    by_repository: dict
