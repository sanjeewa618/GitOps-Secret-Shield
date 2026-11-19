import logging
import secrets
import string
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy import text
from app.providers.base import BaseRotationProvider
from app.database.session import SessionLocal
from app.services.vault_service import vault_service

logger = logging.getLogger(__name__)


class PostgreSQLRotationProvider(BaseRotationProvider):
    """Automated credential rotation provider for PostgreSQL databases."""

    @property
    def provider_name(self) -> str:
        return "PostgreSQL"

    def can_handle(self, detector_name: str) -> bool:
        """Handles database connection strings and database credential leaks."""
        name_lower = detector_name.lower()
        return "database" in name_lower or "postgres" in name_lower or "db_password" in name_lower

    @staticmethod
    def generate_secure_password(length: int = 32) -> str:
        """Generates a cryptographically strong random password."""
        # Mix uppercase, lowercase, numbers, and special characters
        chars = string.ascii_letters + string.digits + "!#%*+,-./:=?@^_~"
        # Ensure at least one from each category
        password = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
            secrets.choice("!#%*+,-./:=?@^_~"),
        ]
        password += [secrets.choice(chars) for _ in range(length - 4)]
        secrets.SystemRandom().shuffle(password)
        return "".join(password)

    def rotate(
        self,
        repository: str,
        incident_id: str,
        detector_name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Rotates database credentials:
        1. Generates strong replacement password.
        2. Applies password rotation to PostgreSQL user.
        3. Persists rotated credential securely into HashiCorp Vault KV v2.
        """
        metadata = metadata or {}
        username = metadata.get("db_user", "app_service_user")
        new_password = self.generate_secure_password(32)

        logger.info(f"Initiating credential rotation for user '{username}' (Incident: {incident_id})")

        # 1. Update PostgreSQL user password
        db_success = False
        db_error = None
        try:
            with SessionLocal() as db:
                # Use parameter escaping safe query or format validated alphanumeric username
                safe_username = "".join(c for c in username if c.isalnum() or c == "_")
                # Quote password safely for SQL string literal
                escaped_password = new_password.replace("'", "''")

                sql_command = f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '{safe_username}') THEN
                        CREATE ROLE {safe_username} WITH LOGIN PASSWORD '{escaped_password}';
                    ELSE
                        ALTER ROLE {safe_username} WITH PASSWORD '{escaped_password}';
                    END IF;
                END
                $$;
                """
                db.execute(text(sql_command))
                db.commit()
                db_success = True
                logger.info(f"PostgreSQL password for role '{safe_username}' successfully updated.")
        except Exception as e:
            db_error = str(e)
            logger.error(f"Failed to update user password in PostgreSQL: {e}")

        if not db_success:
            return {
                "success": False,
                "provider": self.provider_name,
                "status": "failed",
                "remediation_status": "failed",
                "notes": f"Database user rotation query failed: {db_error}",
                "vault_path": None,
            }

        # 2. Store replacement credentials in HashiCorp Vault KV v2
        secret_payload = {
            "db_user": safe_username,
            "db_password": new_password,
            "db_host": "localhost",
            "db_port": 5434,
            "db_name": "secret_shield",
            "rotated_at": datetime.now(timezone.utc).isoformat(),
            "rotated_by": "GitOps-Secret-Shield-AutoRotation",
            "incident_id": incident_id,
        }

        vault_result = vault_service.store_replacement_secret(
            repository=repository,
            incident_id=incident_id,
            secret_data=secret_payload,
        )

        vault_path = vault_result.get("vault_path")
        if not vault_result.get("success"):
            logger.warning(
                f"Password rotated in DB, but Vault storage encountered error: {vault_result.get('error')}"
            )
            return {
                "success": True,  # DB password was rotated
                "provider": self.provider_name,
                "status": "rotation_in_progress",
                "remediation_status": "vault_sync_pending",
                "notes": f"Password rotated in PostgreSQL; Vault sync warning: {vault_result.get('error')}",
                "vault_path": vault_path,
                "replacement_preview": f"{new_password[:4]}...{new_password[-4:]}",
            }

        return {
            "success": True,
            "provider": self.provider_name,
            "status": "rotated",
            "remediation_status": "rotated",
            "notes": f"Successfully rotated credentials for '{safe_username}' in PostgreSQL and stored securely in Vault.",
            "vault_path": vault_path,
            "replacement_preview": f"{new_password[:4]}...{new_password[-4:]}",
        }
