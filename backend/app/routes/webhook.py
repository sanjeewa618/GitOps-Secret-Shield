import os
import json
import logging
from fastapi import APIRouter, Request, HTTPException
from dotenv import load_dotenv
from app.services.github_service import GitHubService
from app.services.scanner_service import ScannerService

load_dotenv()
logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/github")
async def github_webhook(request: Request):
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

    # 5. Process Push Events with Automated Secret Scanning
    if event == "push":
        repo_name = payload.get("repository", {}).get("full_name", "unknown")
        pusher = payload.get("pusher", {}).get("name", "unknown")
        commits = payload.get("commits", [])

        all_findings = []

        # Step 5a: Scan commit messages for sensitive data
        msg_findings = ScannerService.scan_commit_payload(commits)
        all_findings.extend(msg_findings)

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
                            all_findings.append(finding)

        # Step 5c: If secrets are detected, trigger alert
        if all_findings:
            logger.warning(f"🚨 CRITICAL: {len(all_findings)} exposed secrets detected in {repo_name} pushed by {pusher}!")
            return {
                "status": "alert_triggered",
                "event": "push",
                "repository": repo_name,
                "pusher": pusher,
                "commits_scanned": len(commits),
                "total_leaks": len(all_findings),
                "findings": all_findings,
                "remediation_status": "rotation_required"
            }

        return {
            "status": "clean",
            "event": "push",
            "repository": repo_name,
            "pusher": pusher,
            "commits_scanned": len(commits),
            "message": "Pushed commits and changed files scanned successfully. No secrets detected."
        }

    # Handle ping or other events
    return {
        "status": "success",
        "event": event,
        "message": f"GitHub {event} event received and verified successfully."
    }
