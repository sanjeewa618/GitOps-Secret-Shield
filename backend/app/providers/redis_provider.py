import logging
import secrets
import string
from typing import Dict, Any, Optional

from app.providers.base import BaseRotationProvider
from app.services.vault_service import vault_service

logger = logging.getLogger(__name__)

REDIS_DETECTORS = {"Redis", "redis", "RedisCredentials"}


def _generate_secure_password(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*_+-"
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*_+-"),
    ]
    pwd += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)


class RedisRotationProvider(BaseRotationProvider):
    """
    Rotation provider for Redis authentication credentials.

    Supports:
      - Redis 6+ ACL users  (target_user provided)
      - Legacy requirepass   (no target_user → rotates the default password)

    Rotation strategy:
    1. Connect with admin/current credentials.
    2. Set new password via ACL SETUSER or CONFIG SET requirepass.
    3. Verify new credentials connect successfully.
    4. Store replacement credentials in HashiCorp Vault KV v2.
    """

    @property
    def provider_name(self) -> str:
        return "Redis"

    def can_handle(self, detector_name: str) -> bool:
        return detector_name in REDIS_DETECTORS

    def rotate(
        self,
        repository: str,
        incident_id: str,
        detector_name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Rotate Redis credentials.

        Metadata keys:
            host          – Redis hostname (default: localhost)
            port          – Redis port (default: 6379)
            current_pass  – Current Redis password / admin password
            target_user   – ACL username to rotate (omit for requirepass mode)
            db            – Redis database index (default: 0)
        """
        meta = metadata or {}
        host = meta.get("host", "localhost")
        port = int(meta.get("port", 6379))
        current_pass = meta.get("current_pass", "")
        target_user = meta.get("target_user", "")     # empty → requirepass mode
        db_index = int(meta.get("db", 0))

        try:
            import redis as redis_lib  # optional dependency; imported lazily
        except ImportError:
            return {
                "success": False,
                "provider": self.provider_name,
                "incident_id": incident_id,
                "notes": "redis-py not installed. Add 'redis' to requirements.txt and retry.",
            }

        new_password = _generate_secure_password(32)

        try:
            # ── Step 1: Connect with current credentials ──────────────────
            connect_kwargs: Dict[str, Any] = {
                "host": host, "port": port, "db": db_index,
                "socket_connect_timeout": 5,
                "decode_responses": True,
            }
            if current_pass:
                if target_user:
                    connect_kwargs["username"] = target_user
                connect_kwargs["password"] = current_pass

            r = redis_lib.Redis(**connect_kwargs)
            r.ping()

            # ── Step 2: Rotate ────────────────────────────────────────────
            if target_user:
                # Redis 6+ ACL mode
                r.execute_command(
                    "ACL", "SETUSER", target_user,
                    f">>{new_password}",    # append new password to ACL entry
                    "on", "~*", "&*", "+@all",
                )
                # Remove old password from ACL if known
                if current_pass:
                    try:
                        r.execute_command("ACL", "SETUSER", target_user,
                                          f"<{current_pass}")
                    except Exception:
                        pass  # ignore if old pwd already removed
                r.execute_command("ACL", "SAVE")
                logger.info(f"[Redis] ACL password rotated for user '{target_user}' on {host}:{port}")
            else:
                # Legacy requirepass mode
                r.config_set("requirepass", new_password)
                logger.info(f"[Redis] requirepass rotated on {host}:{port}")

            r.close()

            # ── Step 3: Verify new credentials ───────────────────────────
            verify_kwargs = {
                "host": host, "port": port, "db": db_index,
                "password": new_password,
                "socket_connect_timeout": 5,
                "decode_responses": True,
            }
            if target_user:
                verify_kwargs["username"] = target_user
            r_verify = redis_lib.Redis(**verify_kwargs)
            r_verify.ping()
            r_verify.close()
            logger.info(f"[Redis] New credentials verified on {host}:{port}")

        except Exception as exc:
            logger.error(f"[Redis] Rotation failed for incident {incident_id}: {exc}")
            return {
                "success": False,
                "provider": self.provider_name,
                "incident_id": incident_id,
                "notes": f"Redis rotation error: {exc}. Manual remediation required.",
            }

        # ── Step 4: Store in Vault ────────────────────────────────────────
        vault_result = vault_service.store_replacement_secret(
            repository=repository,
            incident_id=incident_id,
            secret_data={
                "provider": "redis",
                "host": host,
                "port": str(port),
                "username": target_user or "default",
                "password": new_password,
                "rotated_for_incident": incident_id,
            },
        )

        if not vault_result.get("success"):
            logger.warning(f"[Redis] Vault sync failed for {incident_id}: {vault_result.get('error')}")
            return {
                "success": True,
                "provider": self.provider_name,
                "incident_id": incident_id,
                "status": "vault_sync_pending",
                "remediation_status": "vault_sync_pending",
                "notes": (
                    f"Redis credentials rotated but Vault sync failed: "
                    f"{vault_result.get('error')}."
                ),
            }

        return {
            "success": True,
            "provider": self.provider_name,
            "incident_id": incident_id,
            "status": "rotated",
            "remediation_status": "rotated",
            "vault_path": vault_result.get("vault_path"),
            "notes": (
                f"Redis credentials rotated successfully. "
                f"New credentials stored in Vault at {vault_result.get('vault_path')}."
            ),
        }
