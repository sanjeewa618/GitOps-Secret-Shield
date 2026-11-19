from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.services.incident_service import IncidentService
from app.services.vault_service import vault_service
from app.services.rotation_service import rotation_service
from app.schemas.incident import (
    IncidentResponse,
    IncidentListResponse,
    IncidentStats,
    IncidentUpdate,
)

router = APIRouter(tags=["Security Incidents & Remediation"])


@router.get("/incidents/stats", response_model=IncidentStats)
def get_incident_stats(db: Session = Depends(get_db)):
    """Retrieve security analytics and aggregate metrics for the dashboard."""
    return IncidentService.get_dashboard_stats(db)


@router.get("/incidents", response_model=IncidentListResponse)
def list_incidents(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    repository: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    """List all recorded security incidents with filtering and pagination."""
    incidents, total = IncidentService.list_incidents(
        db, skip=skip, limit=limit, repository=repository, status=status, severity=severity
    )
    return {
        "total": total,
        "page": (skip // limit) + 1,
        "page_size": limit,
        "incidents": incidents,
    }


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    """Retrieve detailed information for a specific security incident."""
    incident = IncidentService.get_by_incident_id(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return incident


@router.patch("/incidents/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: str,
    update_data: IncidentUpdate,
    db: Session = Depends(get_db),
):
    """Update incident status or remediation information."""
    updated = IncidentService.update_incident(db, incident_id, update_data)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return updated


@router.post("/incidents/{incident_id}/rotate")
def rotate_incident_credential(
    incident_id: str,
    payload: Optional[Dict[str, Any]] = None,
    db: Session = Depends(get_db),
):
    """
    Trigger automated credential rotation for an incident.
    - PostgreSQL: Generates strong password, alters role, stores in Vault, sets status to 'rotated'.
    - Unsupported (AWS, GitHub, Stripe, OpenAI): Sets status to 'manual_remediation_required'.
    """
    metadata = payload or {}
    result = rotation_service.rotate_incident(db, incident_id, metadata=metadata)
    if not result.get("success") and result.get("error"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result.get("error"),
        )
    return result


@router.get("/incidents/{incident_id}/vault")
def get_incident_vault_secret(
    incident_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve rotated credentials directly from HashiCorp Vault for this incident."""
    incident = IncidentService.get_by_incident_id(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    if not incident.vault_secret_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No Vault secret path associated with incident '{incident_id}'",
        )

    secret_data = vault_service.get_secret(incident.repository, incident.incident_id)
    if not secret_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No secret found in Vault for incident '{incident_id}'",
        )

    return {
        "incident_id": incident.incident_id,
        "vault_secret_path": incident.vault_secret_path,
        "secret_data": secret_data,
    }


@router.get("/vault/health")
def get_vault_health():
    """Retrieve HashiCorp Vault system health status."""
    return vault_service.check_health()
