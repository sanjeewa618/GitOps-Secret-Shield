from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from app.database.base import Base


class FalsePositiveRule(Base):
    """Narrowly scoped, time-bound allowlist rules for managing verified false positives."""
    __tablename__ = "false_positive_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    secret_fingerprint: Mapped[str] = mapped_column(String(64), index=True, nullable=True)
    detector_name: Mapped[str] = mapped_column(String(128), nullable=True)
    repository: Mapped[str] = mapped_column(String(255), nullable=True)
    file_path_pattern: Mapped[str] = mapped_column(String(512), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class FalsePositiveAuditLog(Base):
    """Immutable audit log for false-positive rule creation, updates, and deactivation."""
    __tablename__ = "false_positive_audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[int] = mapped_column(Integer, index=True, nullable=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True, nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)  # created, updated, deactivated, incident_marked, incident_unmarked
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
