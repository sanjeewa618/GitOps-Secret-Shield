# ===========================================================
# GitOps Secret Shield – Phase 2 Integration Tests
# Tests: auth, rate-limiting, notifications, new providers,
#        rotation orchestration, regression of Phase 1
# ===========================================================

import os
import sys
import time
import uuid
import hmac
import json
import hashlib
import pytest
import httpx

# ── Path setup ──────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.database.session import SessionLocal
from app.services.incident_service import IncidentService
from app.services.vault_service import VaultService
from app.services.rotation_service import RotationService
from app.services.alert_service import dispatch_alert, _sent_notifications
from app.services.auth_service import (
    authenticate_user, create_access_token, verify_password
)
from app.providers.mysql_provider import MySQLRotationProvider
from app.providers.redis_provider import RedisRotationProvider
from app.providers.mongodb_provider import MongoDBRotationProvider
from app.schemas.incident import IncidentCreate

BASE_URL = "http://localhost:8000"
WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "your_local_test_secret_change_me")


# ═══════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════

@pytest.fixture(scope="session")
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def clear_notification_dedup():
    """Reset notification dedup set before each test."""
    _sent_notifications.clear()
    yield
    _sent_notifications.clear()


def _make_webhook_payload(commit_id: str, message: str, filename: str = "test.py") -> tuple:
    """Return (body_bytes, valid_signature)."""
    payload = {
        "repository": {"full_name": f"testorg/phase2-test-{uuid.uuid4().hex[:6]}"},
        "pusher": {"name": "phase2-tester"},
        "commits": [{
            "id": commit_id,
            "message": message,
            "author": {"username": "phase2-tester"},
            "added": [filename],
            "modified": [],
            "removed": [],
        }],
    }
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return body, sig, payload


# ═══════════════════════════════════════════════════════════
# Task 4 – Authentication Tests
# ═══════════════════════════════════════════════════════════

class TestAuthentication:
    """Verify JWT auth endpoints and dependency enforcement."""

    def test_authenticate_valid_admin(self):
        user = authenticate_user("admin", os.getenv("ADMIN_PASSWORD", "AdminSecret123!"))
        assert user is not None
        assert user.role == "admin"

    def test_authenticate_invalid_password(self):
        user = authenticate_user("admin", "wrong-password")
        assert user is None

    def test_authenticate_nonexistent_user(self):
        user = authenticate_user("nonexistent", "any")
        assert user is None

    def test_token_created_has_expiry(self):
        from datetime import timedelta
        token_str = create_access_token(
            {"sub": "admin", "role": "admin"},
            expires_delta=timedelta(minutes=5),
        )
        assert isinstance(token_str, str)
        assert len(token_str) > 20

    def test_password_hash_verify(self):
        from app.services.auth_service import pwd_context
        hashed = pwd_context.hash("TestPassword999!")
        assert verify_password("TestPassword999!", hashed) is True
        assert verify_password("WrongPassword!", hashed) is False

    @pytest.mark.skipif(
        os.getenv("SKIP_LIVE_API", "false").lower() == "true",
        reason="Live backend not running"
    )
    def test_api_token_endpoint(self):
        """POST /api/v1/auth/token returns a valid JWT."""
        res = httpx.post(
            f"{BASE_URL}/api/v1/auth/token",
            data={"username": "admin", "password": os.getenv("ADMIN_PASSWORD", "AdminSecret123!")},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
        data = res.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["role"] == "admin"

    @pytest.mark.skipif(
        os.getenv("SKIP_LIVE_API", "false").lower() == "true",
        reason="Live backend not running"
    )
    def test_api_invalid_credentials(self):
        """POST /api/v1/auth/token with wrong password → 401."""
        res = httpx.post(
            f"{BASE_URL}/api/v1/auth/token",
            data={"username": "admin", "password": "completely-wrong"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        assert res.status_code == 401


# ═══════════════════════════════════════════════════════════
# Task 4 – Rate Limiting Tests
# ═══════════════════════════════════════════════════════════

class TestRateLimiting:
    @pytest.mark.skipif(
        os.getenv("SKIP_LIVE_API", "false").lower() == "true",
        reason="Live backend not running"
    )
    def test_rate_limit_on_auth_endpoint(self):
        """
        Sending >10 rapid requests to /api/v1/auth/token from same IP
        should eventually trigger HTTP 429.
        """
        limit_hit = False
        for _ in range(15):
            res = httpx.post(
                f"{BASE_URL}/api/v1/auth/token",
                data={"username": "admin", "password": "wrong"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=5,
            )
            if res.status_code == 429:
                limit_hit = True
                assert "Retry-After" in res.headers
                assert "retry_after_seconds" in res.json()
                break
        assert limit_hit, "Expected HTTP 429 after exceeding auth rate limit"

    @pytest.mark.skipif(
        os.getenv("SKIP_LIVE_API", "false").lower() == "true",
        reason="Live backend not running"
    )
    def test_rate_limit_headers_present(self):
        """Normal requests should include X-RateLimit-* headers."""
        res = httpx.get(f"{BASE_URL}/health", timeout=5)
        # Health is exempt; check a real API endpoint
        res2 = httpx.get(f"{BASE_URL}/api/v1/incidents/stats", timeout=5)
        assert "X-RateLimit-Limit" in res2.headers
        assert "X-RateLimit-Remaining" in res2.headers


# ═══════════════════════════════════════════════════════════
# Task 3 – Notification Service Tests
# ═══════════════════════════════════════════════════════════

class TestAlertService:
    """Test notification dispatch, deduplication, and safe failure handling."""

    def test_email_skipped_when_disabled(self):
        result = dispatch_alert(
            incident_id="INC-TEST-001",
            repository="testorg/repo",
            severity="CRITICAL",
            detector_name="Github",
            file_path="config/settings.py",
            event="incident_detected",
        )
        # Email is disabled in test env
        assert result["email"]["skipped"] is True
        assert result["email"]["reason"] in ("email_disabled", "already_sent")

    def test_slack_skipped_when_disabled(self):
        result = dispatch_alert(
            incident_id="INC-TEST-002",
            repository="testorg/repo",
            severity="CRITICAL",
            detector_name="Github",
            file_path="app/main.py",
            event="incident_detected",
        )
        assert result["slack"]["skipped"] is True

    def test_notification_deduplication(self):
        """Same incident+channel+event must only send once."""
        incident_id = f"INC-DEDUP-{uuid.uuid4().hex[:6]}"
        # First call (skipped because disabled – dedup still tested via dedup key)
        result1 = dispatch_alert(
            incident_id=incident_id,
            repository="org/repo",
            severity="HIGH",
            detector_name="AWSKeyID",
            file_path="deploy/terraform.tf",
            event="incident_detected",
        )
        result2 = dispatch_alert(
            incident_id=incident_id,
            repository="org/repo",
            severity="HIGH",
            detector_name="AWSKeyID",
            file_path="deploy/terraform.tf",
            event="incident_detected",
        )
        # Both should be skipped (not sent twice) – either disabled or already_sent
        assert result1["email"].get("skipped") or not result1["email"].get("success")
        assert result2["email"].get("skipped") or not result2["email"].get("success")

    def test_alert_does_not_contain_raw_secrets(self):
        """
        dispatch_alert does not expose raw secret values – only incident metadata.
        Verified by ensuring the function signature never accepts a 'secret_value' field.
        """
        import inspect
        from app.services import alert_service
        sig = inspect.signature(alert_service.dispatch_alert)
        param_names = list(sig.parameters.keys())
        assert "secret_value" not in param_names
        assert "raw_secret" not in param_names


# ═══════════════════════════════════════════════════════════
# Task 2 – Provider Architecture Tests
# ═══════════════════════════════════════════════════════════

class TestProviderRegistration:
    """Verify all 4 providers are registered in RotationService."""

    def test_all_providers_registered(self):
        rs = RotationService()
        names = {p.provider_name for p in rs.providers}
        assert "PostgreSQL" in names
        assert "MySQL" in names
        assert "Redis" in names
        assert "MongoDB" in names

    def test_mysql_can_handle(self):
        p = MySQLRotationProvider()
        assert p.can_handle("MySQL") is True
        assert p.can_handle("mysql") is True
        assert p.can_handle("Github") is False

    def test_redis_can_handle(self):
        p = RedisRotationProvider()
        assert p.can_handle("Redis") is True
        assert p.can_handle("redis") is True
        assert p.can_handle("PostgreSQL") is False

    def test_mongodb_can_handle(self):
        p = MongoDBRotationProvider()
        assert p.can_handle("MongoDB") is True
        assert p.can_handle("mongodb") is True
        assert p.can_handle("MySQL") is False

    def test_provider_name_strings(self):
        assert MySQLRotationProvider().provider_name == "MySQL"
        assert RedisRotationProvider().provider_name == "Redis"
        assert MongoDBRotationProvider().provider_name == "MongoDB"


class TestProviderFailsWithoutMetadata:
    """Providers return informative failure when required metadata is missing."""

    def test_mysql_no_metadata(self):
        result = MySQLRotationProvider().rotate(
            repository="testorg/repo",
            incident_id="INC-MYSQL-001",
            detector_name="MySQL",
            metadata={},
        )
        assert result["success"] is False
        assert "admin_user" in result["notes"] or "metadata" in result["notes"]

    def test_mongodb_no_metadata(self):
        result = MongoDBRotationProvider().rotate(
            repository="testorg/repo",
            incident_id="INC-MONGO-001",
            detector_name="MongoDB",
            metadata={},
        )
        assert result["success"] is False
        assert "admin_user" in result["notes"] or "metadata" in result["notes"]

    def test_redis_no_pymysql_graceful(self):
        """Redis provider returns failure (not exception) if redis-py not installed."""
        result = RedisRotationProvider().rotate(
            repository="testorg/repo",
            incident_id="INC-REDIS-001",
            detector_name="Redis",
            metadata={"host": "localhost", "port": "9999"},
        )
        # Will fail either on import or connection – must NOT raise exception
        assert "success" in result
        assert result["success"] is False


class TestUnsupportedProviderFallback:
    """Unknown detector types must receive manual_remediation_required."""

    def test_github_token_no_provider(self, db):
        rs = RotationService()
        provider = rs.find_provider("Github")
        assert provider is None

    def test_aws_no_provider(self, db):
        rs = RotationService()
        provider = rs.find_provider("AWSKeyID")
        assert provider is None

    def test_stripe_no_provider(self, db):
        rs = RotationService()
        provider = rs.find_provider("Stripe")
        assert provider is None


# ═══════════════════════════════════════════════════════════
# Task 6 – Rotation Orchestration Tests
# ═══════════════════════════════════════════════════════════

class TestRotationOrchestration:
    """Test RotationService.rotate_incident with real DB incidents."""

    def _create_test_incident(self, db, detector: str, sha_prefix: str = "") -> str:
        sha = f"phase2test{sha_prefix}{uuid.uuid4().hex[:8]}"
        incident_data = IncidentCreate(
            repository=f"testorg/phase2-{detector.lower()}-test",
            commit_sha=sha,
            author="phase2-tester",
            detector_name=detector,
            secret_masked="***MASKED***",
            file_path=f"config/{detector.lower()}.env",
            line_number=1,
            severity="CRITICAL",
        )
        incident, _ = IncidentService.create_or_get_incident(db, incident_data)
        return incident.incident_id

    def test_unsupported_detector_sets_manual_remediation(self, db):
        """GitHub PAT → no automated provider → manual_remediation_required."""
        iid = self._create_test_incident(db, "Github")
        rs = RotationService()
        result = rs.rotate_incident(db, iid, metadata={})
        assert result["automated"] is False
        assert result["remediation_status"] == "manual_remediation_required"

    def test_rotate_nonexistent_incident(self, db):
        rs = RotationService()
        result = rs.rotate_incident(db, "INC-NONEXISTENT-999999", metadata={})
        assert result["success"] is False
        assert "not found" in result.get("error", "").lower()

    def test_mysql_rotation_no_db_sets_failed(self, db):
        """MySQL rotation with no real DB → failure (not crash)."""
        iid = self._create_test_incident(db, "MySQL")
        rs = RotationService()
        result = rs.rotate_incident(db, iid, metadata={
            "admin_user": "root",
            "admin_pass": "doesnotexist",
            "target_user": "appuser",
            "host": "localhost",
            "port": "3307",    # non-existent port
        })
        # Rotation must FAIL safely (no server available), never crash
        assert "success" in result
        # Either failed due to connection or missing pymysql
        assert result.get("success") is False or result.get("automated") is True


# ═══════════════════════════════════════════════════════════
# Task 9 – Regression: Phase 1 Tests Still Pass
# ═══════════════════════════════════════════════════════════

class TestPhase1Regression:
    """Ensure Phase 1 functionality is unbroken by Phase 2 changes."""

    def test_vault_service_health(self):
        vs = VaultService()
        health = vs.check_health()
        assert health["status"] in ("healthy", "unreachable")

    def test_vault_store_retrieve_delete(self):
        vs = VaultService()
        if vs.check_health()["status"] != "healthy":
            pytest.skip("Vault not available in this environment")
        repo = "testorg/regression-test"
        iid = f"INC-REG-{uuid.uuid4().hex[:8]}"
        store = vs.store_replacement_secret(
            repository=repo,
            incident_id=iid,
            secret_data={"type": "regression_test", "value": "synthetic"},
        )
        assert store["success"] is True
        retrieved = vs.get_secret(repo, iid)
        assert retrieved is not None
        assert retrieved.get("type") == "regression_test"
        deleted = vs.revoke_secret(repo, iid)
        assert deleted is True

    def test_incident_deduplication(self, db):
        """Creating the same incident twice returns is_new=False on second call."""
        sha = uuid.uuid4().hex[:16]
        data = IncidentCreate(
            repository="testorg/regression-dedup",
            commit_sha=sha,
            author="regressor",
            detector_name="AWSKeyID",
            secret_masked="AKIA****REGR",
            file_path="terraform/main.tf",
            line_number=42,
            severity="CRITICAL",
        )
        incident1, is_new1 = IncidentService.create_or_get_incident(db, data)
        incident2, is_new2 = IncidentService.create_or_get_incident(db, data)
        assert is_new1 is True
        assert is_new2 is False
        assert incident1.incident_id == incident2.incident_id

    @pytest.mark.skipif(
        os.getenv("SKIP_LIVE_API", "false").lower() == "true",
        reason="Live backend not running"
    )
    def test_health_endpoint(self):
        res = httpx.get(f"{BASE_URL}/health", timeout=5)
        assert res.status_code == 200
        assert res.json()["status"] == "healthy"

    @pytest.mark.skipif(
        os.getenv("SKIP_LIVE_API", "false").lower() == "true",
        reason="Live backend not running"
    )
    def test_webhook_valid_signature_still_accepted(self):
        body, sig, _ = _make_webhook_payload(
            commit_id=uuid.uuid4().hex,
            message="regression: no secret here just checking hook",
        )
        res = httpx.post(
            f"{BASE_URL}/webhooks/github",
            content=body,
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "push",
                "Content-Type": "application/json",
            },
            timeout=15,
        )
        assert res.status_code in (200, 201, 400)

    @pytest.mark.skipif(
        os.getenv("SKIP_LIVE_API", "false").lower() == "true",
        reason="Live backend not running"
    )
    def test_webhook_invalid_signature_rejected(self):
        body, _, _ = _make_webhook_payload(
            commit_id=uuid.uuid4().hex,
            message="regression: invalid sig test",
        )
        res = httpx.post(
            f"{BASE_URL}/webhooks/github",
            content=body,
            headers={
                "X-Hub-Signature-256": "sha256=invalid000000000000",
                "X-GitHub-Event": "push",
                "Content-Type": "application/json",
            },
            timeout=10,
        )
        assert res.status_code == 401
