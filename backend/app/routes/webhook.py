import os
import json
import logging
from typing import List, Dict, Any
from fastapi import APIRouter, Request, HTTPException, Depends
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from app.database.session import get_db
from app.models.incident import IncidentStatus
from app.schemas.incident import IncidentCreate
from app.services.incident_service import IncidentService
from app.services.github_service import GitHubService
from app.services.scanner_service import ScannerService
from app.services.false_positive_service import FalsePositiveService

load_dotenv()
logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/github")
async def github_webhook(request: Request, db: Session = Depends(get_db)):
    # 1. Read GitHub webhook secret
    webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not webhook_secret:
        raise HTTPException(
            status_code=500,
            detail="Webhook secret is not configured"
        )

    # 2. Read request body
    body = await request.body()

    # 3. Get and verify GitHub signature
    signature = request.headers.get("X-Hub-Signature-256")
    if not signature:
        raise HTTPException(
            status_code=401,
            detail="Missing GitHub signature"
        )

    if not GitHubService.verify_signature(
        payload_body=body,
        secret_token=webhook_secret,
        signature_header=signature
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid GitHub webhook signature"
        )

    # 4. Identify GitHub Event
    event = request.headers.get("X-GitHub-Event", "ping")

    try:
        payload = json.loads(body.decode("utf-8")) if body else {}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {str(e)}")

    # 5. Process Push Events with Automated Secret Scanning & Audit Logging
    if event == "push":
        repo_name = payload.get("repository", {}).get("full_name", "unknown")
        pusher = payload.get("pusher", {}).get("name", "unknown")
        commits = payload.get("commits", [])

        raw_findings: List[Dict[str, Any]] = []

        # Step 5a: Scan commit messages for sensitive data
        msg_findings = ScannerService.scan_commit_payload(commits)
        raw_findings.extend(msg_findings)

        # Step 5b: Inspect changed files and git diffs for each pushed commit via GitHub API
        for commit in commits:
            commit_sha = commit.get("id")
            if not commit_sha:
                continue

            commit_details = await GitHubService.get_commit_details(repo_name, commit_sha)
            if commit_details:
                for file_info in commit_details.get("files", []):
                    filename = file_info.get("filename", "unknown")
                    patch = file_info.get("patch", "")
                    if patch:
                        patch_findings = ScannerService.scan_text(patch, file_path=filename)
                        for finding in patch_findings:
                            finding["commit_sha"] = commit_sha
                            finding["author"] = pusher
                            raw_findings.append(finding)

        # Step 5c: If secrets are detected, check active false-positive rules, persist audit logs & trigger alert
        if raw_findings:
            persisted_incidents = []
            for finding in raw_findings:
                commit_sha = finding.get("commit_sha", (commits[0].get("id") if commits else "unknown"))
                fp = finding.get("secret_fingerprint")
                suppressed_rule = FalsePositiveService.is_suppressed(
                    db,
                    secret_fingerprint=fp,
                    detector_name=finding.get("detector_name"),
                    repository=repo_name,
                    file_path=finding.get("file_path"),
                )
                if suppressed_rule:
                    logger.info(
                        f"Finding suppressed by active false-positive rule #{suppressed_rule.id} "
                        f"for {repo_name}:{finding.get('file_path')}"
                    )
                    continue

                incident_in = IncidentCreate(
                    repository=repo_name,
                    commit_sha=commit_sha,
                    author=finding.get("author", pusher),
                    detector_name=finding.get("detector_name", "Unknown Secret"),
                    secret_masked=finding.get("raw_secret_masked", "********"),
                    file_path=finding.get("file_path", "unknown"),
                    line_number=finding.get("line_number", 1),
                    severity=finding.get("severity", "CRITICAL"),
                    status=IncidentStatus.ROTATION_REQUIRED.value,
                    remediation_status="rotation_required",
                    remediation_notes=f"Exposed secret detected in push by {pusher} in commit {commit_sha[:7]}",
                    secret_fingerprint=fp,
                    secret_category=finding.get("secret_category", "generic_secret"),
                    risk_score=finding.get("risk_score", 75.0),
                    risk_factors=finding.get("risk_factors"),
                )
                incident_obj, created = IncidentService.create_or_get_incident(db, incident_in)

                persisted_incidents.append({
                    "incident_id": incident_obj.incident_id,
                    "detector_name": incident_obj.detector_name,
                    "secret_masked": incident_obj.secret_masked,
                    "file_path": incident_obj.file_path,
                    "line_number": incident_obj.line_number,
                    "severity": incident_obj.severity,
                    "status": incident_obj.status,
                    "remediation_status": incident_obj.remediation_status,
                    "commit_sha": incident_obj.commit_sha,
                    "author": incident_obj.author,
                    "is_new": created,
                })

            logger.warning(
                f"CRITICAL: {len(persisted_incidents)} secrets recorded in PostgreSQL for {repo_name} pushed by {pusher}!"
            )

            # Optional: Post security alert comment on the commit if possible
            for commit in commits:
                commit_sha = commit.get("id")
                commit_findings = [f for f in persisted_incidents if f["commit_sha"] == commit_sha]
                if commit_findings and commit_sha:
                    findings_summary = "\n".join(
                        [f"- **Incident ID**: `{f['incident_id']}` | **Type**: {f['detector_name']} | **File**: `{f['file_path']}:{f['line_number']}`" for f in commit_findings]
                    )
                    comment_body = (
                        f"### 🛡️ GitOps Secret Shield – Security Alert\n\n"
                        f"The automated security scanner detected **{len(commit_findings)} exposed secret(s)** in this commit:\n\n"
                        f"{findings_summary}\n\n"
                        f"> ⚠️ **Action Required**: The exposed credentials have been logged into the DevSecOps Audit Log. "
                        f"Immediate rotation is required. Never commit plain credentials to version control."
                    )
                    await GitHubService.create_commit_comment(repo_name, commit_sha, comment_body)

            return {
                "status": "alert_triggered",
                "event": "push",
                "repository": repo_name,
                "pusher": pusher,
                "commits_scanned": len(commits),
                "total_leaks": len(persisted_incidents),
                "incidents": persisted_incidents,
                "remediation_status": "rotation_required",
            }

        return {
            "status": "clean",
            "event": "push",
            "repository": repo_name,
            "pusher": pusher,
            "commits_scanned": len(commits),
            "message": "Pushed commits and changed files scanned successfully. No secrets detected.",
        }

    # Handle ping or other events
    return {
        "status": "success",
        "event": event,
        "message": f"GitHub {event} event received and verified successfully.",
    }
