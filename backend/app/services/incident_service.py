import logging
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc
from app.models.incident import Incident, IncidentStatus
from app.schemas.incident import IncidentCreate, IncidentUpdate

logger = logging.getLogger(__name__)


class IncidentService:
    """Service to handle security incident audit log operations in PostgreSQL."""

    @staticmethod
    def create_or_get_incident(db: Session, incident_in: IncidentCreate) -> Tuple[Incident, bool]:
        """
        Idempotently create an incident record.
        If a record for the exact finding already exists (e.g. duplicate webhook delivery),
        it returns the existing record and created=False.
        """
        existing = db.scalars(
            select(Incident).where(
                Incident.repository == incident_in.repository,
                Incident.commit_sha == incident_in.commit_sha,
                Incident.detector_name == incident_in.detector_name,
                Incident.file_path == incident_in.file_path,
                Incident.line_number == incident_in.line_number,
            )
        ).first()

        if existing:
            logger.info(f"Duplicate incident detected for commit {incident_in.commit_sha}. Reusing {existing.incident_id}.")
            return existing, False

        # Create new incident
        db_incident = Incident(
            repository=incident_in.repository,
            commit_sha=incident_in.commit_sha,
            author=incident_in.author or "unknown",
            detector_name=incident_in.detector_name,
            secret_masked=incident_in.secret_masked,
            file_path=incident_in.file_path,
            line_number=incident_in.line_number or 1,
            severity=incident_in.severity or "CRITICAL",
            status=incident_in.status or IncidentStatus.DETECTED.value,
            remediation_status=incident_in.remediation_status or "pending",
            remediation_notes=incident_in.remediation_notes,
            vault_secret_path=incident_in.vault_secret_path,
            secret_fingerprint=incident_in.secret_fingerprint,
            secret_category=incident_in.secret_category or "generic_secret",
            risk_score=incident_in.risk_score if incident_in.risk_score is not None else 75.0,
            risk_factors=incident_in.risk_factors,
            is_false_positive=incident_in.is_false_positive or False,
            false_positive_reason=incident_in.false_positive_reason,
        )

        db.add(db_incident)
        db.commit()
        db.refresh(db_incident)

        # Phase 3: Correlate related incidents by fingerprint / metadata
        from app.services.correlation_service import CorrelationService
        db_incident = CorrelationService.correlate_incident(db, db_incident)

        logger.info(f"Created new security incident {db_incident.incident_id} for {db_incident.repository}")
        return db_incident, True

    @staticmethod
    def get_by_incident_id(db: Session, incident_id: str) -> Optional[Incident]:
        """Retrieve incident by human-readable unique incident ID."""
        return db.scalars(select(Incident).where(Incident.incident_id == incident_id)).first()

    @staticmethod
    def list_incidents(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        repository: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> Tuple[List[Incident], int]:
        """List incidents with filtering and pagination."""
        query = select(Incident)

        if repository:
            query = query.where(Incident.repository == repository)
        if status:
            query = query.where(Incident.status == status)
        if severity:
            query = query.where(Incident.severity == severity)

        total = db.scalar(select(func.count()).select_from(query.subquery()))
        incidents = db.scalars(
            query.order_by(desc(Incident.created_at)).offset(skip).limit(limit)
        ).all()

        return list(incidents), total or 0

    @staticmethod
    def update_incident(db: Session, incident_id: str, update_in: IncidentUpdate) -> Optional[Incident]:
        """Update incident remediation status, notes, or vault path."""
        incident = IncidentService.get_by_incident_id(db, incident_id)
        if not incident:
            return None

        update_data = update_in.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(incident, field, value)

        db.commit()
        db.refresh(incident)
        logger.info(f"Updated incident {incident_id}: status={incident.status}, remediation={incident.remediation_status}")
        return incident

    @staticmethod
    def get_dashboard_stats(db: Session) -> Dict[str, Any]:
        """Compute aggregate statistics for the security dashboard."""
        total = db.scalar(select(func.count(Incident.id))) or 0
        critical = db.scalar(select(func.count(Incident.id)).where(Incident.severity == "CRITICAL")) or 0
        resolved = db.scalar(select(func.count(Incident.id)).where(Incident.status == IncidentStatus.RESOLVED.value)) or 0
        pending_rotations = db.scalar(
            select(func.count(Incident.id)).where(
                Incident.status.in_([
                    IncidentStatus.ROTATION_REQUIRED.value,
                    IncidentStatus.ROTATION_IN_PROGRESS.value
                ])
            )
        ) or 0

        # By Severity
        sev_counts = db.execute(
            select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)
        ).all()
        by_severity = {row[0]: row[1] for row in sev_counts}

        # By Repository
        repo_counts = db.execute(
            select(Incident.repository, func.count(Incident.id)).group_by(Incident.repository)
        ).all()
        by_repository = {row[0]: row[1] for row in repo_counts}

        return {
            "total_incidents": total,
            "critical_incidents": critical,
            "resolved_incidents": resolved,
            "pending_rotations": pending_rotations,
            "by_severity": by_severity,
            "by_repository": by_repository,
        }
