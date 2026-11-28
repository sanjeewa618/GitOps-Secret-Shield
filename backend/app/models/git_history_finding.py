from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.database.base import Base


class GitHistoryFinding(Base):
    """Stores secrets discovered during historical Git commit investigation (masked + fingerprinted only)."""
    __tablename__ = "git_history_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repository: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    commit_message: Mapped[str] = mapped_column(String(512), nullable=True)
    author: Mapped[str] = mapped_column(String(128), nullable=True, default="unknown")
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    line_number: Mapped[int] = mapped_column(Integer, nullable=True, default=1)
    detector_name: Mapped[str] = mapped_column(String(128), nullable=False)
    secret_masked: Mapped[str] = mapped_column(String(255), nullable=False)
    secret_fingerprint: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="HIGH")
    risk_score: Mapped[float] = mapped_column(default=70.0)
    committed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    linked_incident_id: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    remediation_note: Mapped[str] = mapped_column(
        Text,
        default="Historical exposure detected. Removing a secret from Git history does NOT revoke it; rotate or revoke the credential.",
    )
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        UniqueConstraint(
            "repository", "commit_sha", "detector_name", "file_path", "line_number",
            name="uq_git_history_finding",
        ),
    )
