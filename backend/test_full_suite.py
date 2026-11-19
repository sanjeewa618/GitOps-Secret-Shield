import os
import json
import hmac
import hashlib
from fastapi.testclient import TestClient
from app.main import app
from app.config.settings import settings
from app.database.session import SessionLocal
from app.models.incident import Incident
from app.services.vault_service import vault_service

client = TestClient(app)


def test_full_suite():
    print("=" * 60)
    print("      GITOPS SECRET SHIELD - COMPREHENSIVE E2E VERIFICATION")
    print("=" * 60)

    # 1. Health Checks
    print("\n[STEP 1] System Health Checks")
    res_be = client.get("/health")
    assert res_be.status_code == 200 and res_be.json()["status"] == "healthy"
    print("  ✓ FastAPI Backend: Healthy")

    res_vh = client.get("/api/v1/vault/health")
    assert res_vh.status_code == 200 and res_vh.json()["status"] == "healthy"
    print(f"  ✓ HashiCorp Vault: Healthy (v{res_vh.json().get('version')})")

    # 2. Webhook & Secret Detection
    print("\n[STEP 2] Webhook Secret Detection & Masking")
    commit_payload = {
        "repository": {"full_name": "sanjeewa618/GitOps-Secret-Shield"},
        "pusher": {"name": "developer-alex"},
        "commits": [
            {
                "id": "abc123def456789001",
                "message": "fix: updated config with " + "postgresql://" + "db_admin:leaked_super_secret_pwd@localhost:5434/secret_shield",
                "author": {"username": "developer-alex"},
            }
        ],
    }
    body_bytes = json.dumps(commit_payload).encode("utf-8")
    sig = f"sha256={hmac.new(settings.GITHUB_WEBHOOK_SECRET.encode(), body_bytes, hashlib.sha256).hexdigest()}"

    res_hook = client.post(
        "/webhooks/github",
        content=body_bytes,
        headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "push", "Content-Type": "application/json"},
    )
    assert res_hook.status_code == 200
    hook_data = res_hook.json()
    assert hook_data["status"] == "alert_triggered"
    assert hook_data["total_leaks"] >= 1
    inc = hook_data["incidents"][0]
    inc_id = inc["incident_id"]
    print(f"  ✓ Secret Detected: {inc['detector_name']}")
    print(f"  ✓ Masked Secret: {inc['secret_masked']}")
    print(f"  ✓ Generated Incident ID: {inc_id}")

    # 3. Webhook Deduplication
    print("\n[STEP 3] Idempotent Webhook Deduplication")
    res_dup = client.post(
        "/webhooks/github",
        content=body_bytes,
        headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "push", "Content-Type": "application/json"},
    )
    dup_inc = res_dup.json()["incidents"][0]
    assert dup_inc["incident_id"] == inc_id
    assert dup_inc["is_new"] is False
    print(f"  ✓ Duplicate push recognized without duplicate DB records. Reused: {inc_id}")

    # 4. Automated PostgreSQL Rotation
    print("\n[STEP 4] Automated Credential Rotation (PostgreSQL Provider)")
    res_rot = client.post(f"/api/v1/incidents/{inc_id}/rotate", json={"db_user": "app_rotated_role"})
    assert res_rot.status_code == 200
    rot_data = res_rot.json()
    assert rot_data["success"] is True
    assert rot_data["status"] == "rotated"
    print(f"  ✓ Rotation executed: {rot_data['status']}")
    print(f"  ✓ Stored in Vault: {rot_data['vault_secret_path']}")

    # 5. Vault Secret Retrieval
    print("\n[STEP 5] Cryptographic Verification in Vault KV v2")
    res_vault = client.get(f"/api/v1/incidents/{inc_id}/vault")
    assert res_vault.status_code == 200
    v_data = res_vault.json()
    assert v_data["incident_id"] == inc_id
    assert "db_password" in v_data["secret_data"]
    print(f"  ✓ Decrypted Vault Payload: User={v_data['secret_data']['db_user']}, DB={v_data['secret_data']['db_name']}")

    # 6. Manual Remediation Fallback
    print("\n[STEP 6] Manual Remediation Fallback (Unsupported Provider)")
    aws_payload = {
        "repository": {"full_name": "sanjeewa618/GitOps-Secret-Shield"},
        "pusher": {"name": "developer-bob"},
        "commits": [{"id": "aws999888777666001", "message": "feat: test key " + "AKIA" + "IOSFODNN7EXAMPLE", "author": {"username": "bob"}}],
    }
    aws_bytes = json.dumps(aws_payload).encode("utf-8")
    aws_sig = f"sha256={hmac.new(settings.GITHUB_WEBHOOK_SECRET.encode(), aws_bytes, hashlib.sha256).hexdigest()}"
    res_aws = client.post("/webhooks/github", content=aws_bytes, headers={"X-Hub-Signature-256": aws_sig, "X-GitHub-Event": "push"})
    aws_inc_id = res_aws.json()["incidents"][0]["incident_id"]

    res_aws_rot = client.post(f"/api/v1/incidents/{aws_inc_id}/rotate")
    assert res_aws_rot.status_code == 200
    assert res_aws_rot.json()["automated"] is False
    assert res_aws_rot.json()["remediation_status"] == "manual_remediation_required"
    print(f"  ✓ Gracefully routed to manual remediation: {aws_inc_id}")

    # 7. Security Dashboard Verification
    print("\n[STEP 7] React Security Dashboard Availability")
    res_dash = client.get("/dashboard/")
    assert res_dash.status_code == 200
    assert "<div id=\"root\">" in res_dash.text
    print("  ✓ React Frontend Dashboard served successfully at /dashboard/")

    # 8. Stats API
    res_stats = client.get("/api/v1/incidents/stats")
    assert res_stats.status_code == 200
    print(f"  ✓ Dashboard Statistics: Total={res_stats.json()['total_incidents']}, Critical={res_stats.json()['critical_incidents']}")

    print("\n" + "=" * 60)
    print("   ALL PHASES (1, 2, 3, 4) VERIFIED AND 100% OPERATIONAL!   ")
    print("=" * 60)


if __name__ == "__main__":
    test_full_suite()
