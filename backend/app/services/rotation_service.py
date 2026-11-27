import logging
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session
from app.models.incident import Incident, IncidentStatus
from app.schemas.incident import IncidentUpdate
from app.services.incident_service import IncidentService
from app.providers.base import BaseRotationProvider
from app.providers.postgres_provider import PostgreSQLRotationProvider
from app.providers.mysql_provider import MySQLRotationProvider
from app.providers.redis_provider import RedisRotationProvider
from app.providers.mongodb_provider import MongoDBRotationProvider

logger = logging.getLogger(__name__)


class RotationService:
    """
    Orchestrates automated and manual remediation workflows for exposed credentials.
    Phase 2: Extended with MySQL, Redis, MongoDB providers.
    """

    def __init__(self):
        self.providers: List[BaseRotationProvider] = [
            PostgreSQLRotationProvider(),
            MySQLRotationProvider(),
            RedisRotationProvider(),
            MongoDBRotationProvider(),
        ]

    def find_provider(self, detector_name: str) -> Optional[BaseRotationProvider]:
        """Finds the appropriate rotation provider for the given credential type."""
        for provider in self.providers:
            if provider.can_handle(detector_name):
                return provider
        return None

    def rotate_incident(
        self,
        db: Session,
        incident_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Executes credential rotation workflow for a specific incident:
        1. Validates incident exists.
        2. Detects if an automated provider supports this credential type.
        3. If supported, triggers provider rotation, sets PostgreSQL user, stores in Vault, updates status to 'rotated'.
        4. If unsupported (e.g. AWS, Stripe, GitHub, OpenAI), safely sets status to 'manual_remediation_required'.
        """
        incident = IncidentService.get_by_incident_id(db, incident_id)
        if not incident:
            return {
                "success": False,
                "error": f"Incident '{incident_id}' not found.",
                "incident_id": incident_id,
            }

        provider = self.find_provider(incident.detector_name)

        # Fallback to Manual Remediation if no automated provider is configured
        if not provider:
            notes = (
                f"Automated rotation is not currently supported for detector '{incident.detector_name}'. "
                f"Manual remediation required: Revoke key immediately in the {incident.detector_name} console, "
                f"generate new credentials, and update deployment configurations."
            )
            IncidentService.update_incident(
                db,
                incident_id,
                IncidentUpdate(
                    status=IncidentStatus.ROTATION_REQUIRED.value,
                    remediation_status="manual_remediation_required",
                    remediation_notes=notes,
                ),
            )
            logger.info(f"Manual remediation requested for {incident_id} ({incident.detector_name})")
            return {
                "success": False,
                "automated": False,
                "incident_id": incident_id,
                "detector_name": incident.detector_name,
                "status": IncidentStatus.ROTATION_REQUIRED.value,
                "remediation_status": "manual_remediation_required",
                "notes": notes,
            }

        # Automated Rotation Workflow
        logger.info(f"Executing automated rotation for {incident_id} via provider '{provider.provider_name}'")
        IncidentService.update_incident(
            db,
            incident_id,
            IncidentUpdate(
                status=IncidentStatus.ROTATION_IN_PROGRESS.value,
                remediation_status="rotation_in_progress",
            ),
        )

        rotation_result = provider.rotate(
            repository=incident.repository,
            incident_id=incident.incident_id,
            detector_name=incident.detector_name,
            metadata=metadata,
        )

        if rotation_result.get("success"):
            new_status = rotation_result.get("status", IncidentStatus.ROTATED.value)
            vault_path = rotation_result.get("vault_path")
            notes = rotation_result.get("notes", "Credential rotated successfully.")

            updated = IncidentService.update_incident(
                db,
                incident_id,
                IncidentUpdate(
                    status=new_status,
                    remediation_status=rotation_result.get("remediation_status", "rotated"),
                    vault_secret_path=vault_path,
                    remediation_notes=notes,
                ),
            )
            return {
                "success": True,
                "automated": True,
                "provider": provider.provider_name,
                "incident_id": incident_id,
                "status": updated.status if updated else new_status,
                "remediation_status": updated.remediation_status if updated else "rotated",
                "vault_secret_path": vault_path,
                "notes": notes,
            }
        else:
            notes = rotation_result.get("notes", "Automated rotation provider failed.")
            updated = IncidentService.update_incident(
                db,
                incident_id,
                IncidentUpdate(
                    status=IncidentStatus.FAILED.value,
                    remediation_status="failed",
                    remediation_notes=notes,
                ),
            )
            return {
                "success": False,
                "automated": True,
                "provider": provider.provider_name,
                "incident_id": incident_id,
                "status": IncidentStatus.FAILED.value,
                "remediation_status": "failed",
                "notes": notes,
            }


# Singleton instance
rotation_service = RotationService()
