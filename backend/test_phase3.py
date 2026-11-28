# ===========================================================
# GitOps Secret Shield – Phase 3 Test Suite
# Tests: Intelligent detection, entropy, risk scoring,
#        Git history, correlation, remediation dry-run/approval,
#        false-positive expiration, RBAC, masking
# ===========================================================

import os
import sys
import uuid
import subprocess
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.main import app, _apply_phase3_migrations
from app.database.base import Base
from app.database.session import SessionLocal, engine
from app.services.scanner_service import ScannerService
from app.services.risk_scoring_service import RiskScoringService
from app.services.git_history_service import GitHistoryService
from app.services.correlation_service import CorrelationService
from app.services.remediation_service import RemediationService
from app.services.false_positive_service import FalsePositiveService
from app.services.incident_service import IncidentService
from app.services.auth_service import create_access_token
from app.schemas.incident import IncidentCreate

client = TestClient(app)


@pytest.fixture(scope="session", autouse=True)
def ensure_db_schema():
    Base.metadata.create_all(bind=engine)
    _apply_phase3_migrations()


@pytest.fixture(scope="session")
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def admin_headers():
    token = create_access_token({"sub": "admin", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def dev_headers():
    token = create_access_token({"sub": "developer", "role": "developer"})
    return {"Authorization": f"Bearer {token}"}


# ═══════════════════════════════════════════════════════════
# Task 1 – Intelligent Secret Detection
# ═══════════════════════════════════════════════════════════

class TestIntelligentDetection:
    def test_synthetic_regex_key_detected_and_masked(self):
        # Construct synthetic key dynamically to avoid static literal triggers
        synthetic_aws = "AKIA" + "IOSFODNN7EXAMPLE"
        findings = ScannerService.scan_text(f'AWS_KEY="{synthetic_aws}"', file_path="config/prod.env")
        assert len(findings) >= 1
        assert findings[0]["detector_name"] == "AWS Access Key"
        assert synthetic_aws not in findings[0]["raw_secret_masked"]
        assert len(findings[0]["secret_fingerprint"]) == 32

    def test_high_entropy_unknown_format_detected(self):
        # Synthetic high-entropy token constructed dynamically for test isolation
        random_token = "".join(["v9K2", "mP8x", "Q4zL", "7wR3", "nJ6t", "Y5bF", "1cH0", "dG9sA"])
        findings = ScannerService.scan_text(f"SERVICE_CUSTOM_CRED='{random_token}'", file_path="deploy/prod.yml")
        assert len(findings) >= 1
        assert findings[0]["raw_secret_masked"] != random_token
        assert findings[0]["risk_score"] > 0

    def test_context_aware_secret_detected(self):
        synthetic_val = "".join(["Zx9!", "kL2@", "mP7#", "qR4$", "wT8"])
        findings = ScannerService.scan_text(f'internal_signing_secret = "{synthetic_val}"', file_path="app/auth.py")
        assert len(findings) >= 1

    def test_ordinary_strings_do_not_trigger_false_positives(self):
        benign_code = (
            'user_id = "550e8400-e29b-41d4-a716-446655440000"\n'
            'docs_url = "https://github.com/sanjeewa618/GitOps-Secret-Shield"\n'
            'api_key = "your_secret_placeholder_example"\n'
            'app_name = "GitOpsSecretShieldApplication"\n'
        )
        findings = ScannerService.scan_text(benign_code, file_path="README.md")
        assert findings == []


# ═══════════════════════════════════════════════════════════
# Task 2 – Classification & Risk Scoring
# ═══════════════════════════════════════════════════════════

class TestClassificationAndRiskScoring:
    def test_classification_categories(self):
        assert RiskScoringService.classify_detector("AWS Access Key") == "cloud_iam"
        assert RiskScoringService.classify_detector("PostgreSQL") == "database_credential"
        assert RiskScoringService.classify_detector("GitHub Personal Access Token") == "vcs_token"
        assert RiskScoringService.classify_detector("Stripe Secret Key") == "payment_key"

    def test_risk_score_varies_by_location_and_verification(self):
        svc = RiskScoringService()
        prod_active = svc.evaluate_finding("AWS Access Key", file_path="prod/.env", verification_status="active")
        docs_unverified = svc.evaluate_finding("AWS Access Key", file_path="docs/README.md", verification_status="unverified")
        revoked = svc.evaluate_finding("AWS Access Key", file_path="prod/.env", verification_status="revoked")

        assert prod_active["severity"] == "CRITICAL"
        assert prod_active["risk_score"] > docs_unverified["risk_score"]
        assert revoked["risk_score"] < prod_active["risk_score"]
        assert prod_active["risk_factors_dict"]["risk_assessment_type"] == "verified"
        assert docs_unverified["risk_factors_dict"]["risk_assessment_type"] == "estimated"


# ═══════════════════════════════════════════════════════════
# Task 3 – Git History Leak Investigation
# ═══════════════════════════════════════════════════════════

class TestGitHistoryInvestigation:
    def test_historical_secret_detected_in_isolated_repo(self, tmp_path, db):
        repo_dir = tmp_path / "hist_repo"
        repo_dir.mkdir()
        subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo_dir, check=True)

        # Commit 1: exposes synthetic secret
        synthetic_pat = "".join(["ghp_", "A1B2C3", "D4E5F6", "G7H8I9", "J0K1L2", "M3N4O5", "P6Q7R8"])
        secret_file = repo_dir / "config.py"
        secret_file.write_text(f'TOKEN = "{synthetic_pat}"\n')
        subprocess.run(["git", "add", "config.py"], cwd=repo_dir, check=True)
        subprocess.run(["git", "commit", "-m", "initial commit"], cwd=repo_dir, check=True, capture_output=True)

        # Commit 2: removes secret from latest commit
        secret_file.write_text('TOKEN = os.getenv("TOKEN")\n')
        subprocess.run(["git", "add", "config.py"], cwd=repo_dir, check=True)
        subprocess.run(["git", "commit", "-m", "remove token"], cwd=repo_dir, check=True, capture_output=True)

        repo_name = f"testorg/hist-{uuid.uuid4().hex[:6]}"
        res = GitHistoryService.scan_repository_history(db, str(repo_dir), repository_name=repo_name, max_commits=10)
        assert res["success"] is True
        assert res["commits_scanned"] == 2
        assert res["findings_count"] >= 1
        # Raw secret must NEVER appear in finding
        for f in res["findings"]:
            assert synthetic_pat not in str(f)


# ═══════════════════════════════════════════════════════════
# Task 4 – Incident Correlation & Duplicate Prevention
# ═══════════════════════════════════════════════════════════

class TestIncidentCorrelation:
    def test_same_fingerprint_correlates_across_commits(self, db):
        fp = uuid.uuid4().hex
        repo = f"testorg/corr-{uuid.uuid4().hex[:6]}"
        inc1, created1 = IncidentService.create_or_get_incident(
            db,
            IncidentCreate(
                repository=repo,
                commit_sha=uuid.uuid4().hex[:12],
                detector_name="GitHub Personal Access Token",
                secret_masked="ghp_...Q7R8",
                file_path="a.py",
                line_number=1,
                secret_fingerprint=fp,
                secret_category="vcs_token",
                risk_score=90.0,
            ),
        )
        inc2, created2 = IncidentService.create_or_get_incident(
            db,
            IncidentCreate(
                repository=repo,
                commit_sha=uuid.uuid4().hex[:12],
                detector_name="GitHub Personal Access Token",
                secret_masked="ghp_...Q7R8",
                file_path="b.py",
                line_number=5,
                secret_fingerprint=fp,
                secret_category="vcs_token",
                risk_score=90.0,
            ),
        )
        assert created1 is True and created2 is True
        assert inc1.correlation_group_id == inc2.correlation_group_id

        corr = CorrelationService.get_correlated_incidents(db, inc1.incident_id)
        assert corr["found"] is True
        assert corr["occurrence_count"] == 2
        assert any(r["incident_id"] == inc2.incident_id for r in corr["related"])


# ═══════════════════════════════════════════════════════════
# Task 5 – Automated Remediation Workflow (Dry-run & Approval)
# ═══════════════════════════════════════════════════════════

class TestRemediationWorkflow:
    def test_dry_run_and_approval_enforcement(self, db):
        inc, _ = IncidentService.create_or_get_incident(
            db,
            IncidentCreate(
                repository=f"testorg/rem-{uuid.uuid4().hex[:6]}",
                commit_sha=uuid.uuid4().hex[:12],
                detector_name="PostgreSQL",
                secret_masked="post...1234",
                file_path=".env",
                line_number=1,
            ),
        )
        # Dry-run succeeds without changing status
        dry = RemediationService.execute_remediation(db, inc.incident_id, actor="admin", dry_run=True)
        assert dry["success"] is True
        assert dry["dry_run"] is True

        # Execution without approval is blocked
        unapproved = RemediationService.execute_remediation(db, inc.incident_id, actor="admin", dry_run=False, approved=False)
        assert unapproved["success"] is False
        assert unapproved["requires_approval"] is True


# ═══════════════════════════════════════════════════════════
# Task 6 – False Positive Management & RBAC API Tests
# ═══════════════════════════════════════════════════════════

class TestFalsePositiveAndRBAC:
    def test_expired_rule_does_not_suppress(self, db):
        fp = uuid.uuid4().hex
        expired_at = datetime.now(timezone.utc) - timedelta(days=1)
        rule = FalsePositiveService.create_rule(
            db,
            actor="admin",
            reason="Expired test rule",
            secret_fingerprint=fp,
            expires_at=expired_at,
        )
        assert rule.is_active is True
        assert FalsePositiveService.is_suppressed(db, secret_fingerprint=fp) is None

    def test_active_rule_suppresses_matching_fingerprint(self, db):
        fp = uuid.uuid4().hex
        rule = FalsePositiveService.create_rule(
            db,
            actor="admin",
            reason="Synthetic fixture",
            secret_fingerprint=fp,
            expires_in_days=7,
        )
        matched = FalsePositiveService.is_suppressed(db, secret_fingerprint=fp)
        assert matched is not None
        assert matched.id == rule.id
        FalsePositiveService.deactivate_rule(db, rule.id, actor="admin")

    def test_rbac_blocks_developer_on_admin_endpoints(self, dev_headers, admin_headers):
        # Developer cannot create false-positive rule
        r_dev = client.post(
            "/api/v1/false-positives",
            json={"secret_fingerprint": uuid.uuid4().hex, "reason": "dev attempt", "expires_in_days": 5},
            headers=dev_headers,
        )
        assert r_dev.status_code == 403

        # Admin can create and deactivate
        r_admin = client.post(
            "/api/v1/false-positives",
            json={"secret_fingerprint": uuid.uuid4().hex, "reason": "admin verified", "expires_in_days": 5},
            headers=admin_headers,
        )
        assert r_admin.status_code == 201
        rule_id = r_admin.json()["id"]

        r_del = client.delete(f"/api/v1/false-positives/{rule_id}", headers=admin_headers)
        assert r_del.status_code == 200
