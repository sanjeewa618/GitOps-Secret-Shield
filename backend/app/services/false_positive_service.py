"""
False Positive Management Service
Phase 3 – Task 6: GitOps Secret Shield

Allows authorized admins to:
  - Mark/unmark specific incidents as false positives
  - Create narrowly scoped, expiring allowlist rules
  - Audit all allowlist rule changes
  - Ensure expired rules never suppress detections
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from app.models.false_positive import FalsePositiveRule, FalsePositiveAuditLog
from app.models.incident import Incident

logger = logging.getLogger(__name__)


class FalsePositiveService:
    """Manages scoped, expiring false-positive rules and incident flags."""

    @staticmethod
    def create_rule(
        db: Session,
        actor: str,
        reason: str,
        secret_fingerprint: Optional[str] = None,
        detector_name: Optional[str] = None,
        repository: Optional[str] = None,
        file_path_pattern: Optional[str] = None,
        expires_in_days: int = 30,
        expires_at: Optional[datetime] = None,
    ) -> FalsePositiveRule:
        """
        Create a narrowly scoped allowlist rule.
        Requires at least one scope constraint (fingerprint, detector+file, or repository+file)
        to prevent broad scanning bypasses.
        """
        if not secret_fingerprint and not (detector_name and file_path_pattern):
            raise ValueError(
                "Allowlist rule must be narrowly scoped: provide secret_fingerprint or both detector_name and file_path_pattern."
            )

        exp = expires_at or (datetime.now(timezone.utc) + timedelta(days=max(1, expires_in_days)))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)

        rule = FalsePositiveRule(
            secret_fingerprint=secret_fingerprint,
            detector_name=detector_name,
            repository=repository,
            file_path_pattern=file_path_pattern,
            reason=reason,
            created_by=actor,
            is_active=True,
            expires_at=exp,
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)

        audit = FalsePositiveAuditLog(
            rule_id=rule.id,
            action="created",
            actor=actor,
            details=f"Rule #{rule.id} created (expires {exp.isoformat()}): {reason}",
        )
        db.add(audit)
        db.commit()
        return rule

    @staticmethod
    def is_suppressed(
        db: Session,
        secret_fingerprint: Optional[str] = None,
        detector_name: Optional[str] = None,
        repository: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> Optional[FalsePositiveRule]:
        """
        Check if a finding matches an active, non-expired allowlist rule.
        Expired rules NEVER suppress detections.
        """
        now = datetime.now(timezone.utc)
        rules = list(
            db.scalars(
                select(FalsePositiveRule).where(FalsePositiveRule.is_active == True)  # noqa: E712
            ).all()
        )
        for rule in rules:
            exp = rule.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= now:
                continue  # Expired rule must not suppress

            if rule.secret_fingerprint and secret_fingerprint == rule.secret_fingerprint:
                if not rule.repository or rule.repository == repository:
                    return rule

            if (
                rule.detector_name
                and rule.file_path_pattern
                and detector_name == rule.detector_name
                and file_path
                and rule.file_path_pattern in file_path
            ):
                if not rule.repository or rule.repository == repository:
                    return rule

        return None

    @staticmethod
    def mark_incident_false_positive(
        db: Session,
        incident_id: str,
        is_false_positive: bool,
        reason: str,
        actor: str,
    ) -> Optional[Incident]:
        incident = db.scalars(
            select(Incident).where(Incident.incident_id == incident_id)
        ).first()
        if not incident:
            return None

        incident.is_false_positive = is_false_positive
        incident.false_positive_reason = reason if is_false_positive else None
        if is_false_positive:
            incident.status = "resolved"
            incident.remediation_status = "false_positive"
            incident.remediation_notes = f"Marked as false positive by {actor}: {reason}"
        else:
            incident.status = "rotation_required"
            incident.remediation_status = "rotation_required"
            incident.remediation_notes = f"False positive flag cleared by {actor}: {reason}"

        db.commit()
        db.refresh(incident)

        audit = FalsePositiveAuditLog(
            incident_id=incident_id,
            action="incident_marked" if is_false_positive else "incident_unmarked",
            actor=actor,
            details=reason,
        )
        db.add(audit)
        db.commit()
        return incident

    @staticmethod
    def deactivate_rule(db: Session, rule_id: int, actor: str) -> Optional[FalsePositiveRule]:
        rule = db.scalars(
            select(FalsePositiveRule).where(FalsePositiveRule.id == rule_id)
        ).first()
        if not rule:
            return None

        rule.is_active = False
        db.commit()
        db.refresh(rule)

        audit = FalsePositiveAuditLog(
            rule_id=rule.id,
            action="deactivated",
            actor=actor,
            details=f"Rule #{rule.id} deactivated by {actor}",
        )
        db.add(audit)
        db.commit()
        return rule

    @staticmethod
    def list_rules(db: Session, include_inactive: bool = False) -> List[FalsePositiveRule]:
        query = select(FalsePositiveRule)
        if not include_inactive:
            query = query.where(FalsePositiveRule.is_active == True)  # noqa: E712
        return list(db.scalars(query.order_by(desc(FalsePositiveRule.created_at))).all())

    @staticmethod
    def list_audit_logs(db: Session, limit: int = 50) -> List[FalsePositiveAuditLog]:
        return list(
            db.scalars(
                select(FalsePositiveAuditLog)
                .order_by(desc(FalsePositiveAuditLog.created_at))
                .limit(limit)
            ).all()
        )
