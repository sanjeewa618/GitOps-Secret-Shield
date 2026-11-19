# Phase 2 and 3 Automated Tests
from fastapi.testclient import TestClient
from app.main import app
from app.database.session import SessionLocal
from app.models.incident import Incident, IncidentStatus
from app.schemas.incident import IncidentCreate
from app.services.incident_service import IncidentService
from app.services.vault_service import vault_service

client = TestClient(app)


def test_phases_2_and_3():
    print("=== [PHASE 2 - TEST 1] HashiCorp Vault Health Check Endpoint ===")
    res = client.get("/api/v1/vault/health")
    assert res.status_code == 200, f"Vault health check failed: {res.text}"
    data = res.json()
    print("Vault Health Response:", data)
    assert data["status"] == "healthy"
    assert data["initialized"] is True
    assert data["sealed"] is False
    print(" PASS: HashiCorp Vault is healthy and unsealed.")

    print("\n=== [PHASE 2 - TEST 2] Direct Vault Service Write and Read ===")
    test_repo = "sanjeewa618/GitOps-Secret-Shield"
    test_inc_id = "INC-TEST-VAULT-001"
    secret_payload = {"api_key": "test_super_secret_value", "env": "prod"}
    
    store_res = vault_service.store_replacement_secret(test_repo, test_inc_id, secret_payload)
    assert store_res["success"] is True, f"Vault store failed: {store_res}"
    print(f" PASS: Secret stored at Vault path: {store_res['vault_path']}")

    retrieved = vault_service.get_secret(test_repo, test_inc_id)
    assert retrieved == secret_payload, f"Expected {secret_payload}, got {retrieved}"
    print(" PASS: Secret retrieved from Vault successfully matches written data.")

    print("\n=== [PHASE 3 - TEST 3] Automated PostgreSQL Credential Rotation ===")
    with SessionLocal() as db:
        # Create an incident with a database credential leak
        db_incident_in = IncidentCreate(
            repository="sanjeewa618/GitOps-Secret-Shield",
            commit_sha="a1b2c3d4e5f67890db001",
            author="sanjeewa-dev",
            detector_name="Database Credentials URI",
            secret_masked="postgres://" + "app_svc:********@localhost:5434/db",
            file_path="config/database.env",
            line_number=12,
            severity="CRITICAL",
            status=IncidentStatus.ROTATION_REQUIRED.value,
            remediation_status="rotation_required",
            remediation_notes="Database credentials leaked in public commit.",
        )
        db_incident, _ = IncidentService.create_or_get_incident(db, db_incident_in)
        db_incident_id = db_incident.incident_id

    print(f"Created Database Leak Incident: {db_incident_id}")

    # Trigger rotation via API endpoint
    res_rotate = client.post(
        f"/api/v1/incidents/{db_incident_id}/rotate",
        json={"db_user": "app_service_test_user"},
    )
    assert res_rotate.status_code == 200, f"Rotation API call failed: {res_rotate.text}"
    rot_data = res_rotate.json()
    print("Rotation API Response:", rot_data)
    assert rot_data["success"] is True
    assert rot_data["status"] == "rotated"
    assert rot_data["remediation_status"] == "rotated"
    assert rot_data["vault_secret_path"] is not None
    print(f" PASS: Automated rotation succeeded! Vault Path: {rot_data['vault_secret_path']}")

    # Verify secret is accessible via incident vault endpoint
    print("\n=== [PHASE 3 - TEST 4] Retrieve Rotated Credential from Vault via API ===")
    res_vault = client.get(f"/api/v1/incidents/{db_incident_id}/vault")
    assert res_vault.status_code == 200, f"Failed to retrieve secret from vault: {res_vault.text}"
    vault_data = res_vault.json()
    assert vault_data["incident_id"] == db_incident_id
    assert "db_password" in vault_data["secret_data"]
    assert vault_data["secret_data"]["db_user"] == "app_service_test_user"
    print(f" PASS: Rotated secret fetched successfully from Vault via Incident endpoint.")
    print(f"       Stored DB User: {vault_data['secret_data']['db_user']}")
    print(f"       Rotated Timestamp: {vault_data['secret_data']['rotated_at']}")

    print("\n=== [PHASE 3 - TEST 5] Manual Remediation Fallback for Unsupported Provider ===")
    with SessionLocal() as db:
        aws_incident_in = IncidentCreate(
            repository="sanjeewa618/GitOps-Secret-Shield",
            commit_sha="fedcba9876543210aws001",
            author="sanjeewa-dev",
            detector_name="AWS Access Key",
            secret_masked="AKIA...1234",
            file_path="infra/terraform.tfvars",
            line_number=45,
            severity="CRITICAL",
            status=IncidentStatus.ROTATION_REQUIRED.value,
            remediation_status="rotation_required",
            remediation_notes="AWS Access Key leaked in terraform file.",
        )
        aws_incident, _ = IncidentService.create_or_get_incident(db, aws_incident_in)
        aws_incident_id = aws_incident.incident_id

    print(f"Created AWS Key Leak Incident: {aws_incident_id}")

    # Trigger rotation on AWS key
    res_aws_rotate = client.post(f"/api/v1/incidents/{aws_incident_id}/rotate")
    assert res_aws_rotate.status_code == 200
    aws_rot_data = res_aws_rotate.json()
    print("AWS Rotation Response:", aws_rot_data)
    assert aws_rot_data["success"] is False
    assert aws_rot_data["automated"] is False
    assert aws_rot_data["remediation_status"] == "manual_remediation_required"
    assert "manual remediation required" in aws_rot_data["notes"].lower()
    print(" PASS: Unsupported provider correctly falls back to manual remediation required.")

    # Check that the database record reflects manual remediation
    res_aws_check = client.get(f"/api/v1/incidents/{aws_incident_id}")
    assert res_aws_check.status_code == 200
    assert res_aws_check.json()["remediation_status"] == "manual_remediation_required"
    print(" PASS: Database reflects status=rotation_required and remediation_status=manual_remediation_required.")

    print("\n ALL PHASE 2 & PHASE 3 TESTS PASSED PERFECTLY! ")


if __name__ == "__main__":
    test_phases_2_and_3()
