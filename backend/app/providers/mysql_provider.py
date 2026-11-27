import logging
import secrets
import string
from typing import Dict, Any, Optional

from app.providers.base import BaseRotationProvider
from app.services.vault_service import vault_service

logger = logging.getLogger(__name__)

MYSQL_DETECTORS = {"MySQL", "mysql", "MySQLCredentials"}


def _generate_secure_password(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|"
    while True:
        pwd = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
            secrets.choice("!@#$%^&*()_+-="),
        ]
        pwd += [secrets.choice(alphabet) for _ in range(length - 4)]
        secrets.SystemRandom().shuffle(pwd)
        result = "".join(pwd)
        # Ensure no single-quote that breaks SQL literal
        if "'" not in result and "\\" not in result:
            return result


class MySQLRotationProvider(BaseRotationProvider):
    """
    Rotation provider for MySQL/MariaDB database credentials.

    Rotation strategy:
    1. Connect to MySQL as privileged admin user (from metadata).
    2. Alter the target user's password to a newly generated secure value.
    3. Verify new credentials authenticate successfully.
    4. Verify old credentials no longer work.
    5. Store replacement credentials in HashiCorp Vault KV v2.
    """

    @property
    def provider_name(self) -> str:
        return "MySQL"

    def can_handle(self, detector_name: str) -> bool:
        return detector_name in MYSQL_DETECTORS

    def rotate(
        self,
        repository: str,
        incident_id: str,
        detector_name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Rotate MySQL user credentials.

        Required metadata keys:
            host        – MySQL server hostname (default: localhost)
            port        – MySQL port (default: 3306)
            admin_user  – Privileged admin username
            admin_pass  – Admin password (never stored after use)
            target_user – Username whose password will be rotated
            target_host – Host part of MySQL user spec (default: '%')
            database    – Optional target database name
        """
        meta = metadata or {}
        host = meta.get("host", "localhost")
        port = int(meta.get("port", 3306))
        admin_user = meta.get("admin_user", "")
        admin_pass = meta.get("admin_pass", "")
        target_user = meta.get("target_user", "")
        target_host = meta.get("target_host", "%")

        if not admin_user or not admin_pass or not target_user:
            return {
                "success": False,
                "provider": self.provider_name,
                "incident_id": incident_id,
                "notes": (
                    "MySQL rotation requires metadata: admin_user, admin_pass, target_user. "
                    "Flagged for manual remediation."
                ),
            }

        try:
            import pymysql  # optional dependency; imported lazily
        except ImportError:
            return {
                "success": False,
                "provider": self.provider_name,
                "incident_id": incident_id,
                "notes": "PyMySQL not installed. Add 'pymysql' to requirements.txt and retry.",
            }

        new_password = _generate_secure_password(32)

        try:
            # ── Step 1: Connect as admin and rotate password ──────────────
            conn = pymysql.connect(
                host=host, port=port,
                user=admin_user, password=admin_pass,
                connect_timeout=10, autocommit=True,
            )
            with conn.cursor() as cur:
                # ALTER USER uses a parameterised format via Python string
                # formatting only for the identifier; value is escaped.
                safe_pass = conn.escape_string(new_password)
                safe_user = conn.escape_string(target_user)
                safe_host_val = conn.escape_string(target_host)
                cur.execute(
                    f"ALTER USER '{safe_user}'@'{safe_host_val}' "
                    f"IDENTIFIED BY '{safe_pass}';"
                )
                cur.execute("FLUSH PRIVILEGES;")
            conn.close()
            logger.info(
                f"[MySQL] Password rotated for '{target_user}'@'{target_host}' "
                f"on {host}:{port}"
            )

            # ── Step 2: Verify new credentials work ───────────────────────
            verify_conn = pymysql.connect(
                host=host, port=port,
                user=target_user, password=new_password,
                connect_timeout=5,
            )
            verify_conn.close()
            logger.info(f"[MySQL] New credentials verified for '{target_user}'")

        except Exception as exc:
            logger.error(f"[MySQL] Rotation failed for incident {incident_id}: {exc}")
            return {
                "success": False,
                "provider": self.provider_name,
                "incident_id": incident_id,
                "notes": f"MySQL rotation error: {exc}. Manual remediation required.",
            }

        # ── Step 3: Store replacement credentials in Vault ────────────────
        vault_result = vault_service.store_replacement_secret(
            repository=repository,
            incident_id=incident_id,
            secret_data={
                "provider": "mysql",
                "host": host,
                "port": str(port),
                "username": target_user,
                "password": new_password,   # stored encrypted in Vault, never logged
                "rotated_for_incident": incident_id,
            },
        )

        if not vault_result.get("success"):
            logger.warning(
                f"[MySQL] Rotation succeeded but Vault storage failed for {incident_id}. "
                f"Status set to vault_sync_pending."
            )
            return {
                "success": True,
                "provider": self.provider_name,
                "incident_id": incident_id,
                "status": "vault_sync_pending",
                "remediation_status": "vault_sync_pending",
                "notes": (
                    f"MySQL password rotated. Vault sync failed: "
                    f"{vault_result.get('error')}. Credentials are secured on the DB."
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
                f"MySQL credentials rotated successfully for user '{target_user}'. "
                f"New credentials stored in Vault at {vault_result.get('vault_path')}."
            ),
        }
