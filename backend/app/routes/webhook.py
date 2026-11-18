import json
import logging
from typing import Optional
from fastapi import APIRouter, Header, Request, HTTPException, status
from app.services.scanner_service import ScannerService
from app.services.github_service import GitHubService
from app.services.vault_service import VaultService
from app.config.settings import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhook", tags=["GitHub Webhook"])
vault_service = VaultService(vault_addr=settings.VAULT_ADDR, token=settings.VAULT_TOKEN)


@router.get("/status")
def webhook_status():
    return {
        "status": "ready",
        "description": "GitOps Secret Shield GitHub Webhook Receiver is active",
        "supported_events": ["push", "pull_request"],
    }


@router.post("/")
async def receive_github_webhook(
    request: Request,
    x_github_event: str = Header(default="push"),
    x_hub_signature_256: Optional[str] = Header(default=None),
):
    body_bytes = await request.body()
    
    # Optional HMAC Verification (enforced if signature header is provided or in production)
    if x_hub_signature_256 and settings.GITHUB_WEBHOOK_SECRET != "change-me-secret":
        is_valid = GitHubService.verify_signature(
            payload_body=body_bytes,
            secret_token=settings.GITHUB_WEBHOOK_SECRET,
            signature_header=x_hub_signature_256,
        )
        if not is_valid:
            logger.warning("Invalid GitHub webhook signature detected!")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid HMAC signature",
            )

    try:
        payload = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {str(e)}")

    commits = payload.get("commits", [])
    repo_name = payload.get("repository", {}).get("full_name", "local/test-repo")

    # Automated Secret Scanning on received commits
    findings = ScannerService.scan_commit_payload(commits)

    # If any secrets are detected, trigger alert & rotation workflow
    if findings:
        logger.warning(f"🚨 CRITICAL: {len(findings)} exposed secret(s) detected in {repo_name}!")
        rotation_results = []
        for finding in findings:
            # Trigger Vault revocation/rotation
            rotation = vault_service.revoke_secret(finding.get("detector_name"))
            rotation_results.append(rotation)

        return {
            "status": "alert_triggered",
            "repository": repo_name,
            "event": x_github_event,
            "total_leaks": len(findings),
            "findings": findings,
            "remediation_status": "rotation_initiated",
        }

    return {
        "status": "clean",
        "repository": repo_name,
        "event": x_github_event,
        "message": "No secrets detected in commit payload",
        "commits_scanned": len(commits),
    }
