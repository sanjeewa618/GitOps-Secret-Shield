"""
Automated Remediation Workflow Service
Phase 3 – Task 5: GitOps Secret Shield

Provides:
  - Provider-aware remediation recommendations
  - Dry-run preview mode (no external modifications)
  - Manual admin approval workflow (RBAC enforced at route level)
  - Concurrent/duplicate remediation guard
  - Integration with existing rotation_service (no duplicate provider code)
  - Persistent RemediationAuditLog entries
"""

import logging
from typing import Dict, Any, Optional, List

from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from app.models.incident import Incident, IncidentStatus
from app.models.remediation_audit import RemediationAuditLog
from app.services.incident_service import IncidentService
from app.services.rotation_service import rotation_service

logger = logging.getLogger(__name__)


class RemediationService:
    """Orchestrates dry-run, manual approval, and verified automated remediation."""

    @staticmethod
    def build_remediation_plan(db: Session, incident_id: str) -> Dict[str, Any]:
        """Generate a remediation recommendation and dry-run preview without modifying state."""
        incident = IncidentService.get_by_incident_id(db, incident_id)
        if not incident:
            return {"found": False, "incident_id": incident_id, "error": "Incident not found"}

        provider = rotation_service.find_provider(incident.detector_name)
        if provider:
            return {
                "found": True,
                "incident_id": incident.incident_id,
                "detector_name": incident.detector_name,
                "automated_supported": True,
                "provider_name": provider.provider_name,
                "requires_admin_approval": True,
                "proposed_action": (
                    f"Connect to {provider.provider_name}, generate a 32-char high-entropy password, "
                    f"rotate target credential, verify new credential authentication, and store "
                    f"replacement in HashiCorp Vault KV v2."
                ),
                "current_status": incident.status,
                "risk_score": incident.risk_score,
                "security_notice": (
                    "Saving a replacement credential in Vault does not revoke the original credential "
                    "unless the provider confirms rotation and verification succeeds."
                ),
            }

        return {
            "found": True,
            "incident_id": incident.incident_id,
            "detector_name": incident.detector_name,
            "automated_supported": False,
            "provider_name": None,
            "requires_admin_approval": True,
            "proposed_action": (
                f"Automated rotation is not supported for '{incident.detector_name}'. "
                f"Manual remediation required: revoke the exposed credential in the "
                f"{incident.detector_name} console, generate a new key, and update CI/CD secrets."
            ),
            "current_status": incident.status,
            "risk_score": incident.risk_score,
            "security_notice": (
                "Unsupported credentials are never automatically modified or revoked."
            ),
        }

    @classmethod
    def execute_remediation(
        cls,
        db: Session,
        incident_id: str,
        actor: str,
        dry_run: bool = False,
        approved: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute or dry-run remediation for an incident:
        - dry_run=True: records dry_run audit log and returns preview without changing credentials.
        - dry_run=False: requires approved=True, prevents concurrent/duplicate rotation,
          delegates to rotation_service, and records verified audit result.
        """
        incident = IncidentService.get_by_incident_id(db, incident_id)
        if not incident:
            return {"success": False, "error": f"Incident '{incident_id}' not found."}

        plan = cls.build_remediation_plan(db, incident_id)
        provider_name = plan.get("provider_name")

        # Mode A: Dry-run preview
        if dry_run:
            audit = RemediationAuditLog(
                incident_id=incident_id,
                action_type="dry_run",
                provider_name=provider_name,
                dry_run=True,
                approved_by=actor,
                status="planned",
                verified=False,
                details=plan["proposed_action"],
            )
            db.add(audit)
            db.commit()
            return {
                "success": True,
                "dry_run": True,
                "incident_id": incident_id,
                "plan": plan,
                "message": "Dry-run completed. No external credentials were modified.",
            }

        # Mode B: Require manual admin approval
        if not approved:
            return {
                "success": False,
                "dry_run": False,
                "incident_id": incident_id,
                "requires_approval": True,
                "error": "Manual administrator approval (approved=true) is required to execute remediation.",
            }

        # Guard against concurrent or duplicate rotation
        if incident.status == IncidentStatus.ROTATION_IN_PROGRESS.value:
            return {
                "success": False,
                "incident_id": incident_id,
                "error": "Remediation is already in progress for this incident.",
            }
        if incident.status == IncidentStatus.ROTATED.value:
            return {
                "success": False,
                "incident_id": incident_id,
                "error": "Incident credential is already rotated.",
            }

        # Mode C: Execute via existing rotation_service
        result = rotation_service.rotate_incident(db, incident_id, metadata=metadata or {})
        verified = bool(result.get("success") and result.get("status") == "rotated")

        audit = RemediationAuditLog(
            incident_id=incident_id,
            action_type="auto_rotate" if result.get("automated") else "manual_remediation",
            provider_name=provider_name,
            dry_run=False,
            approved_by=actor,
            status=result.get("remediation_status", "failed"),
            verified=verified,
            details=result.get("notes", ""),
        )
        db.add(audit)
        db.commit()

        return {
            **result,
            "dry_run": False,
            "approved_by": actor,
            "verified": verified,
        }

    @staticmethod
    def get_audit_history(db: Session, incident_id: str) -> List[RemediationAuditLog]:
        return list(
            db.scalars(
                select(RemediationAuditLog)
                .where(RemediationAuditLog.incident_id == incident_id)
                .order_by(desc(RemediationAuditLog.created_at))
            ).all()
        )
