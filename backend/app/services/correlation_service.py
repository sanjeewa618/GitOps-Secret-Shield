"""
Advanced Incident Correlation Service
Phase 3 – Task 4: GitOps Secret Shield

Correlates related security incidents by:
  1. Secure secret fingerprint (exact same secret exposed in multiple commits/files)
  2. Repository + secret category + file path metadata (without merging unrelated secrets)
Tracks first_seen_at, last_seen_at, occurrence_count, and correlation_group_id.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from app.models.incident import Incident

logger = logging.getLogger(__name__)


class CorrelationService:
    """Correlates related and duplicate security incidents."""

    @staticmethod
    def compute_correlation_group_id(
        repository: str,
        secret_fingerprint: Optional[str],
        secret_category: Optional[str],
        file_path: str,
    ) -> str:
        """
        Compute a deterministic correlation group ID.
        - If secret_fingerprint is present, group by (repository, secret_fingerprint)
          so the exact same secret across different commits/files is correlated.
        - Otherwise fall back to (repository, secret_category, file_path) so
          unrelated secrets are never merged.
        """
        if secret_fingerprint:
            raw = f"fp:{repository}:{secret_fingerprint}"
        else:
            raw = f"meta:{repository}:{secret_category or 'generic'}:{file_path}"
        return f"CORR-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12].upper()}"

    @classmethod
    def correlate_incident(cls, db: Session, incident: Incident) -> Incident:
        """
        Assign correlation_group_id and update first_seen_at / last_seen_at /
        occurrence_count across matching incidents in the same group.
        """
        group_id = cls.compute_correlation_group_id(
            repository=incident.repository,
            secret_fingerprint=incident.secret_fingerprint,
            secret_category=incident.secret_category,
            file_path=incident.file_path,
        )
        incident.correlation_group_id = group_id
        now = incident.created_at or datetime.now(timezone.utc)

        related = list(
            db.scalars(
                select(Incident).where(Incident.correlation_group_id == group_id)
            ).all()
        )
        if not related:
            incident.occurrence_count = 1
            incident.first_seen_at = now
            incident.last_seen_at = now
        else:
            all_times = [r.first_seen_at or r.created_at for r in related if (r.first_seen_at or r.created_at)]
            all_times.append(now)
            first_seen = min(all_times)
            last_seen = max(all_times)
            count = len(related) + (0 if incident in related else 1)

            for r in related:
                r.occurrence_count = count
                r.first_seen_at = first_seen
                r.last_seen_at = last_seen

            incident.occurrence_count = count
            incident.first_seen_at = first_seen
            incident.last_seen_at = last_seen

        db.commit()
        db.refresh(incident)
        return incident

    @staticmethod
    def get_correlated_incidents(db: Session, incident_id: str) -> Dict[str, Any]:
        """Return all incidents correlated with the given incident_id."""
        target = db.scalars(
            select(Incident).where(Incident.incident_id == incident_id)
        ).first()
        if not target:
            return {"found": False, "incident_id": incident_id, "related": []}

        if not target.correlation_group_id:
            return {
                "found": True,
                "incident_id": incident_id,
                "correlation_group_id": None,
                "occurrence_count": target.occurrence_count or 1,
                "related": [],
            }

        related = list(
            db.scalars(
                select(Incident)
                .where(
                    Incident.correlation_group_id == target.correlation_group_id,
                    Incident.incident_id != incident_id,
                )
                .order_by(desc(Incident.created_at))
            ).all()
        )

        return {
            "found": True,
            "incident_id": incident_id,
            "correlation_group_id": target.correlation_group_id,
            "occurrence_count": target.occurrence_count or (len(related) + 1),
            "first_seen_at": target.first_seen_at.isoformat() if target.first_seen_at else None,
            "last_seen_at": target.last_seen_at.isoformat() if target.last_seen_at else None,
            "related": [
                {
                    "incident_id": r.incident_id,
                    "repository": r.repository,
                    "commit_sha": r.commit_sha,
                    "file_path": r.file_path,
                    "line_number": r.line_number,
                    "detector_name": r.detector_name,
                    "severity": r.severity,
                    "status": r.status,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in related
            ],
        }

    @staticmethod
    def list_correlation_groups(db: Session) -> List[Dict[str, Any]]:
        """Summarize correlation groups across all incidents."""
        incidents = list(db.scalars(select(Incident).order_by(desc(Incident.created_at))).all())
        groups: Dict[str, Dict[str, Any]] = {}
        for inc in incidents:
            gid = inc.correlation_group_id or f"SINGLE-{inc.incident_id}"
            if gid not in groups:
                groups[gid] = {
                    "correlation_group_id": gid,
                    "repository": inc.repository,
                    "detector_name": inc.detector_name,
                    "secret_category": inc.secret_category or "generic_secret",
                    "occurrence_count": 0,
                    "first_seen_at": inc.first_seen_at or inc.created_at,
                    "last_seen_at": inc.last_seen_at or inc.created_at,
                    "incident_ids": [],
                }
            g = groups[gid]
            g["occurrence_count"] += 1
            g["incident_ids"].append(inc.incident_id)
            ts = inc.created_at
            if ts and g["first_seen_at"] and ts < g["first_seen_at"]:
                g["first_seen_at"] = ts
            if ts and g["last_seen_at"] and ts > g["last_seen_at"]:
                g["last_seen_at"] = ts

        return [
            {
                **g,
                "first_seen_at": g["first_seen_at"].isoformat() if g["first_seen_at"] else None,
                "last_seen_at": g["last_seen_at"].isoformat() if g["last_seen_at"] else None,
            }
            for g in groups.values()
        ]
