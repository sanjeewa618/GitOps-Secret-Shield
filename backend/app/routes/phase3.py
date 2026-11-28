"""
Phase 3 API Routes – Advanced Security & Intelligence
Endpoints:
  - Git History Investigation:   POST /git-history/scan, GET /git-history/findings
  - Incident Correlation:        GET /incidents/{id}/correlated, GET /correlations
  - Automated Remediation:       GET /incidents/{id}/remediation/plan,
                                 POST /incidents/{id}/remediation/execute,
                                 GET /incidents/{id}/remediation/audit
  - False Positive Management:   GET /false-positives, POST /false-positives,
                                 DELETE /false-positives/{rule_id},
                                 PATCH /incidents/{id}/false-positive,
                                 GET /false-positives/audit
"""

import os
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.services.auth_service import require_admin, require_developer, UserInDB
from app.services.git_history_service import GitHistoryService
from app.services.correlation_service import CorrelationService
from app.services.remediation_service import RemediationService
from app.services.false_positive_service import FalsePositiveService

router = APIRouter(tags=["Phase 3 – Security Intelligence"])


# ── Request Schemas ───────────────────────────────────────────────────────────

class GitHistoryScanRequest(BaseModel):
    repo_path: Optional[str] = None
    repository_name: str = "sanjeewa618/GitOps-Secret-Shield"
    max_commits: int = Field(default=25, ge=1, le=200)


class RemediationExecuteRequest(BaseModel):
    dry_run: bool = False
    approved: bool = False
    metadata: Optional[Dict[str, Any]] = None


class FalsePositiveRuleCreate(BaseModel):
    secret_fingerprint: Optional[str] = None
    detector_name: Optional[str] = None
    repository: Optional[str] = None
    file_path_pattern: Optional[str] = None
    reason: str = Field(..., min_length=3, max_length=500)
    expires_in_days: int = Field(default=30, ge=1, le=365)
    expires_at: Optional[datetime] = None


class IncidentFalsePositiveRequest(BaseModel):
    is_false_positive: bool = True
    reason: str = Field(..., min_length=3, max_length=500)


# ── Task 3: Git History Investigation ─────────────────────────────────────────

@router.post("/git-history/scan")
def scan_git_history(
    payload: GitHistoryScanRequest,
    db: Session = Depends(get_db),
    current_user: UserInDB = Depends(require_admin),
):
    """Scan historical Git commits for leaked credentials (Admin only)."""
    default_repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    target_path = payload.repo_path or default_repo
    result = GitHistoryService.scan_repository_history(
        db=db,
        repo_path=target_path,
        repository_name=payload.repository_name,
        max_commits=payload.max_commits,
    )
    if not result.get("success"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result.get("error"))
    return result


@router.get("/git-history/findings")
def list_git_history_findings(
    repository: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Retrieve historical Git leak findings (masked + fingerprinted only)."""
    findings = GitHistoryService.list_findings(db, repository=repository, limit=limit)
    return {
        "total": len(findings),
        "findings": [
            {
                "id": f.id,
                "repository": f.repository,
                "commit_sha": f.commit_sha,
                "commit_message": f.commit_message,
                "author": f.author,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "detector_name": f.detector_name,
                "secret_masked": f.secret_masked,
                "secret_fingerprint": f.secret_fingerprint,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "committed_at": f.committed_at.isoformat() if f.committed_at else None,
                "linked_incident_id": f.linked_incident_id,
                "remediation_note": f.remediation_note,
            }
            for f in findings
        ],
    }


# ── Task 4: Incident Correlation ──────────────────────────────────────────────

@router.get("/incidents/{incident_id}/correlated")
def get_correlated_incidents(incident_id: str, db: Session = Depends(get_db)):
    """Retrieve incidents correlated with the specified incident."""
    result = CorrelationService.get_correlated_incidents(db, incident_id)
    if not result.get("found"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return result


@router.get("/correlations")
def list_correlation_groups(db: Session = Depends(get_db)):
    """List all correlated incident groups."""
    groups = CorrelationService.list_correlation_groups(db)
    return {"total": len(groups), "groups": groups}


# ── Task 5: Automated Remediation Workflow ────────────────────────────────────

@router.get("/incidents/{incident_id}/remediation/plan")
def get_remediation_plan(incident_id: str, db: Session = Depends(get_db)):
    """Preview remediation recommendation for an incident."""
    plan = RemediationService.build_remediation_plan(db, incident_id)
    if not plan.get("found"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return plan


@router.post("/incidents/{incident_id}/remediation/execute")
def execute_remediation(
    incident_id: str,
    payload: RemediationExecuteRequest,
    db: Session = Depends(get_db),
    current_user: UserInDB = Depends(require_admin),
):
    """Execute dry-run or admin-approved automated remediation (Admin only)."""
    result = RemediationService.execute_remediation(
        db=db,
        incident_id=incident_id,
        actor=current_user.username,
        dry_run=payload.dry_run,
        approved=payload.approved,
        metadata=payload.metadata,
    )
    if not result.get("success") and "not found" in str(result.get("error", "")).lower():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=result.get("error"))
    if result.get("requires_approval"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result.get("error"))
    return result


@router.get("/incidents/{incident_id}/remediation/audit")
def get_remediation_audit(incident_id: str, db: Session = Depends(get_db)):
    """Retrieve remediation audit trail for an incident."""
    logs = RemediationService.get_audit_history(db, incident_id)
    return {
        "incident_id": incident_id,
        "total": len(logs),
        "audit_logs": [
            {
                "id": l.id,
                "action_type": l.action_type,
                "provider_name": l.provider_name,
                "dry_run": l.dry_run,
                "approved_by": l.approved_by,
                "status": l.status,
                "verified": l.verified,
                "details": l.details,
                "created_at": l.created_at.isoformat() if l.created_at else None,
            }
            for l in logs
        ],
    }


# ── Task 6: False Positive Management ─────────────────────────────────────────

@router.get("/false-positives")
def list_false_positive_rules(
    include_inactive: bool = Query(default=False),
    db: Session = Depends(get_db),
):
    """List false-positive allowlist rules."""
    rules = FalsePositiveService.list_rules(db, include_inactive=include_inactive)
    return {
        "total": len(rules),
        "rules": [
            {
                "id": r.id,
                "secret_fingerprint": r.secret_fingerprint,
                "detector_name": r.detector_name,
                "repository": r.repository,
                "file_path_pattern": r.file_path_pattern,
                "reason": r.reason,
                "created_by": r.created_by,
                "is_active": r.is_active,
                "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rules
        ],
    }


@router.post("/false-positives", status_code=status.HTTP_201_CREATED)
def create_false_positive_rule(
    payload: FalsePositiveRuleCreate,
    db: Session = Depends(get_db),
    current_user: UserInDB = Depends(require_admin),
):
    """Create a narrowly scoped, expiring false-positive allowlist rule (Admin only)."""
    try:
        rule = FalsePositiveService.create_rule(
            db=db,
            actor=current_user.username,
            reason=payload.reason,
            secret_fingerprint=payload.secret_fingerprint,
            detector_name=payload.detector_name,
            repository=payload.repository,
            file_path_pattern=payload.file_path_pattern,
            expires_in_days=payload.expires_in_days,
            expires_at=payload.expires_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return {
        "id": rule.id,
        "secret_fingerprint": rule.secret_fingerprint,
        "detector_name": rule.detector_name,
        "repository": rule.repository,
        "file_path_pattern": rule.file_path_pattern,
        "reason": rule.reason,
        "created_by": rule.created_by,
        "is_active": rule.is_active,
        "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
    }


@router.delete("/false-positives/{rule_id}")
def deactivate_false_positive_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: UserInDB = Depends(require_admin),
):
    """Deactivate a false-positive allowlist rule (Admin only)."""
    rule = FalsePositiveService.deactivate_rule(db, rule_id, actor=current_user.username)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule {rule_id} not found")
    return {"success": True, "rule_id": rule.id, "is_active": rule.is_active}


@router.patch("/incidents/{incident_id}/false-positive")
def mark_incident_false_positive(
    incident_id: str,
    payload: IncidentFalsePositiveRequest,
    db: Session = Depends(get_db),
    current_user: UserInDB = Depends(require_admin),
):
    """Mark or unmark an incident as a false positive (Admin only)."""
    updated = FalsePositiveService.mark_incident_false_positive(
        db=db,
        incident_id=incident_id,
        is_false_positive=payload.is_false_positive,
        reason=payload.reason,
        actor=current_user.username,
    )
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found")
    return {
        "success": True,
        "incident_id": updated.incident_id,
        "is_false_positive": updated.is_false_positive,
        "false_positive_reason": updated.false_positive_reason,
        "status": updated.status,
        "remediation_status": updated.remediation_status,
    }


@router.get("/false-positives/audit")
def list_false_positive_audit(
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: UserInDB = Depends(require_developer),
):
    """Retrieve false-positive audit trail (Developer or Admin)."""
    logs = FalsePositiveService.list_audit_logs(db, limit=limit)
    return {
        "total": len(logs),
        "audit_logs": [
            {
                "id": l.id,
                "rule_id": l.rule_id,
                "incident_id": l.incident_id,
                "action": l.action,
                "actor": l.actor,
                "details": l.details,
                "created_at": l.created_at.isoformat() if l.created_at else None,
            }
            for l in logs
        ],
    }
