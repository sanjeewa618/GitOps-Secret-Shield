import os
import hmac
import hashlib
import json
from fastapi import APIRouter, Request, HTTPException
from dotenv import load_dotenv

load_dotenv()

router = APIRouter()


@router.post("/github")
async def github_webhook(request: Request):
    # Read GitHub webhook secret
    webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not webhook_secret:
        raise HTTPException(
            status_code=500,
            detail="Webhook secret is not configured"
        )

    # Read request body
    body = await request.body()

    # Get GitHub signature
    signature = request.headers.get("X-Hub-Signature-256")
    if not signature:
        raise HTTPException(
            status_code=401,
            detail="Missing GitHub signature"
        )

    # Verify webhook signature using HMAC-SHA256
    expected_signature = "sha256=" + hmac.new(
        webhook_secret.encode("utf-8"),
        body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, signature):
        raise HTTPException(
            status_code=401,
            detail="Invalid GitHub webhook signature"
        )

    # Identify GitHub Event
    event = request.headers.get("X-GitHub-Event", "ping")

    try:
        payload = json.loads(body.decode("utf-8")) if body else {}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {str(e)}")

    # Process Push events
    if event == "push":
        repo_name = payload.get("repository", {}).get("full_name", "unknown")
        pusher = payload.get("pusher", {}).get("name", "unknown")
        commits = payload.get("commits", [])

        return {
            "status": "success",
            "event": "push",
            "repository": repo_name,
            "pusher": pusher,
            "commit_count": len(commits),
            "message": "Webhook received and signature verified. Ready for secret scanning."
        }

    # Handle ping or other events
    return {
        "status": "success",
        "event": event,
        "message": f"GitHub {event} event received and verified successfully."
    }
