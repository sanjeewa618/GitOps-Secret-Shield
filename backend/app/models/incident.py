import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, UniqueConstraint, Enum, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.database.base import Base
import enum


class IncidentStatus(str, enum.Enum):
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    ROTATION_REQUIRED = "rotation_required"
    ROTATION_IN_PROGRESS = "rotation_in_progress"
    ROTATED = "rotated"
    FAILED = "failed"
    RESOLVED = "resolved"


def generate_incident_id() -> str:
    """Generate human-readable unique incident ID: INC-YYYYMMDD-<6 char hex>"""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    unique_suffix = uuid.uuid4().hex[:6].upper()
    return f"INC-{date_str}-{unique_suffix}"


class Incident(Base):
    """SQLAlchemy model for tracking security incident audit logs."""
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=generate_incident_id)
    repository: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    author: Mapped[str] = mapped_column(String(128), nullable=True, default="unknown")
    detector_name: Mapped[str] = mapped_column(String(128), nullable=False)
    secret_masked: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    line_number: Mapped[int] = mapped_column(Integer, nullable=True, default=1)
    severity: Mapped[str] = mapped_column(String(32), default="CRITICAL")
    status: Mapped[str] = mapped_column(String(32), default=IncidentStatus.DETECTED.value, index=True)
    remediation_status: Mapped[str] = mapped_column(String(64), default="pending")
    remediation_notes: Mapped[str] = mapped_column(Text, nullable=True)
    vault_secret_path: Mapped[str] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Deduplication constraint: Prevent duplicate incident records for the same finding in the same commit
    __table_args__ = (
        UniqueConstraint(
            "repository", "commit_sha", "detector_name", "file_path", "line_number",
            name="uq_incident_commit_file_finding"
        ),
    )
