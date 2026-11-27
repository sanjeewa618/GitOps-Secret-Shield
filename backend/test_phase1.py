import hmac
import hashlib
import json
import uuid
from fastapi.testclient import TestClient
from app.main import app
from app.config.settings import settings
from app.database.session import SessionLocal
from app.models.incident import Incident
from sqlalchemy import delete

client = TestClient(app)


def generate_signature(secret: str, payload_bytes: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def test_audit_logging_lifecycle():
    print("=== [TEST 1] Backend Health Check ===")
    res = client.get("/health")
    assert res.status_code == 200, f"Health check failed: {res.text}"
    assert res.json().get("status") == "healthy"
    print(" PASS: Backend /health is OK")

    webhook_secret = settings.GITHUB_WEBHOOK_SECRET
    print(f"Using webhook secret: {webhook_secret[:4]}***")

    # Clean push test
    print("\n=== [TEST 2] Webhook Clean Push Test ===")
    clean_payload = {
        "repository": {"full_name": "sanjeewa618/GitOps-Secret-Shield"},
        "pusher": {"name": "test-dev"},
        "commits": [
            {
                "id": "c1a2b3c4d5e6f7001",
                "message": "feat: update documentation and fix typing",
                "author": {"username": "test-dev"},
            }
        ],
    }
    clean_bytes = json.dumps(clean_payload).encode("utf-8")
    sig = generate_signature(webhook_secret, clean_bytes)

    res = client.post(
        "/webhooks/github",
        content=clean_bytes,
        headers={
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "push",
            "Content-Type": "application/json",
        },
    )
    assert res.status_code == 200, f"Clean push failed: {res.text}"
    data = res.json()
    assert data["status"] == "clean", f"Expected clean, got {data['status']}"
    print(f" PASS: Clean push successfully processed: {data['message']}")

    # Secret push test
    print("\n=== [TEST 3] Webhook Secret Detection & Audit Logging ===")
    unique_commit_sha = f"test_{uuid.uuid4().hex[:16]}"
    secret_payload = {
        "repository": {"full_name": "sanjeewa618/GitOps-Secret-Shield"},
        "pusher": {"name": "devsecops-engineer"},
        "commits": [
            {
                "id": unique_commit_sha,
                "message": "fix: accidentally committed key " + "AKIA" + "IOSFODNN7EXAMPLE for s3 access",
                "author": {"username": "devsecops-engineer"},
            }
        ],
    }
    secret_bytes = json.dumps(secret_payload).encode("utf-8")
    sig = generate_signature(webhook_secret, secret_bytes)

    res = client.post(
        "/webhooks/github",
        content=secret_bytes,
        headers={
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "push",
            "Content-Type": "application/json",
        },
    )
    assert res.status_code == 200, f"Secret push failed: {res.text}"
    data = res.json()
    assert data["status"] == "alert_triggered", f"Expected alert_triggered, got {data}"
    assert data["total_leaks"] >= 1
    incident = data["incidents"][0]
    incident_id = incident["incident_id"]
    assert incident_id.startswith("INC-"), f"Invalid incident_id format: {incident_id}"
    assert incident["secret_masked"] == "AKIA...MPLE", f"Unexpected secret mask: {incident['secret_masked']}"
    assert incident["is_new"] is True, "First finding should have is_new=True"
    print(f" PASS: Secret detected and logged to PostgreSQL with Incident ID: {incident_id}")
    print(f"       Masked Secret: {incident['secret_masked']}")
    print(f"       Status: {incident['status']}")

    # Deduplication test
    print("\n=== [TEST 4] Webhook Deduplication Test ===")
    res_dup = client.post(
        "/webhooks/github",
        content=secret_bytes,
        headers={
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "push",
            "Content-Type": "application/json",
        },
    )
    assert res_dup.status_code == 200
    dup_data = res_dup.json()
    dup_incident = dup_data["incidents"][0]
    assert dup_incident["incident_id"] == incident_id, "Deduplication failed to return existing incident_id"
    assert dup_incident["is_new"] is False, "Duplicate should have is_new=False"
    print(f" PASS: Deduplication successful! Reused incident {incident_id} without duplicate records.")

    # REST API: List incidents
    print("\n=== [TEST 5] Incidents REST API List & Filter ===")
    res_list = client.get("/api/v1/incidents")
    assert res_list.status_code == 200
    list_data = res_list.json()
    assert list_data["total"] >= 1
    found_ids = [inc["incident_id"] for inc in list_data["incidents"]]
    assert incident_id in found_ids
    print(f" PASS: Incident list contains {list_data['total']} recorded incidents.")

    # REST API: Stats
    print("\n=== [TEST 6] Incidents REST API Stats ===")
    res_stats = client.get("/api/v1/incidents/stats")
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert stats["total_incidents"] >= 1
    assert stats["critical_incidents"] >= 1
    print(f" PASS: Dashboard Stats: Total={stats['total_incidents']}, Critical={stats['critical_incidents']}, PendingRotations={stats['pending_rotations']}")

    # REST API: Single Incident
    print("\n=== [TEST 7] Retrieve Single Incident ===")
    res_single = client.get(f"/api/v1/incidents/{incident_id}")
    assert res_single.status_code == 200
    assert res_single.json()["incident_id"] == incident_id
    print(f" PASS: Successfully retrieved details for {incident_id}")

    # REST API: Update Incident
    print("\n=== [TEST 8] Update Incident Status ===")
    res_patch = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "investigating", "remediation_notes": "SOC team has started investigation"},
    )
    assert res_patch.status_code == 200
    updated = res_patch.json()
    assert updated["status"] == "investigating"
    assert updated["remediation_notes"] == "SOC team has started investigation"
    print(f" PASS: Successfully updated {incident_id} status to 'investigating'")

    # Cleanup test data for isolation
    with SessionLocal() as db:
        db.execute(delete(Incident).where(Incident.commit_sha == unique_commit_sha))
        db.commit()

    print("\n ALL PHASE 1 TESTS PASSED SUCCESSFULLY! ")


if __name__ == "__main__":
    test_audit_logging_lifecycle()
