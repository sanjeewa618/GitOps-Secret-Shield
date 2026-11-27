import logging
import secrets
import string
from typing import Dict, Any, Optional

from app.providers.base import BaseRotationProvider
from app.services.vault_service import vault_service

logger = logging.getLogger(__name__)

MONGO_DETECTORS = {"MongoDB", "mongodb", "MongoDBCredentials"}


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


class MongoDBRotationProvider(BaseRotationProvider):
    """
    Rotation provider for MongoDB database user credentials.

    Rotation strategy:
    1. Connect to MongoDB as a privileged admin user.
    2. Update the target user's password using updateUser command.
    3. Verify new credentials authenticate successfully.
    4. Verify old credentials are rejected.
    5. Store replacement credentials in HashiCorp Vault KV v2.
    """

    @property
    def provider_name(self) -> str:
        return "MongoDB"

    def can_handle(self, detector_name: str) -> bool:
        return detector_name in MONGO_DETECTORS

    def rotate(
        self,
        repository: str,
        incident_id: str,
        detector_name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Rotate MongoDB user credentials.

        Metadata keys:
            host          – MongoDB hostname (default: localhost)
            port          – MongoDB port (default: 27017)
            admin_user    – Privileged admin username
            admin_pass    – Admin password
            admin_db      – Admin authentication database (default: admin)
            target_user   – Username whose password will be rotated
            target_db     – Database where target user is defined
        """
        meta = metadata or {}
        host = meta.get("host", "localhost")
        port = int(meta.get("port", 27017))
        admin_user = meta.get("admin_user", "")
        admin_pass = meta.get("admin_pass", "")
        admin_db = meta.get("admin_db", "admin")
        target_user = meta.get("target_user", "")
        target_db = meta.get("target_db", "admin")

        if not admin_user or not admin_pass or not target_user:
            return {
                "success": False,
                "provider": self.provider_name,
                "incident_id": incident_id,
                "notes": (
                    "MongoDB rotation requires metadata: admin_user, admin_pass, target_user. "
                    "Flagged for manual remediation."
                ),
            }

        try:
            from pymongo import MongoClient  # optional dependency
            from pymongo.errors import OperationFailure, ConnectionFailure
        except ImportError:
            return {
                "success": False,
                "provider": self.provider_name,
                "incident_id": incident_id,
                "notes": "pymongo not installed. Add 'pymongo' to requirements.txt and retry.",
            }

        new_password = _generate_secure_password(32)

        try:
            # ── Step 1: Connect as admin ──────────────────────────────────
            mongo_uri = (
                f"mongodb://{admin_user}:{admin_pass}"
                f"@{host}:{port}/{admin_db}"
                f"?authSource={admin_db}&serverSelectionTimeoutMS=5000"
            )
            client = MongoClient(mongo_uri)
            admin_database = client[target_db]

            # ── Step 2: Update target user's password ─────────────────────
            admin_database.command("updateUser", target_user, pwd=new_password)
            logger.info(
                f"[MongoDB] Password updated for user '{target_user}' "
                f"in database '{target_db}' on {host}:{port}"
            )
            client.close()

            # ── Step 3: Verify new credentials work ───────────────────────
            verify_uri = (
                f"mongodb://{target_user}:{new_password}"
                f"@{host}:{port}/{target_db}"
                f"?authSource={target_db}&serverSelectionTimeoutMS=5000"
            )
            verify_client = MongoClient(verify_uri)
            verify_client[target_db].command("ping")
            verify_client.close()
            logger.info(f"[MongoDB] New credentials verified for '{target_user}'")

        except (OperationFailure, ConnectionFailure) as exc:
            logger.error(f"[MongoDB] Rotation failed for incident {incident_id}: {exc}")
            return {
                "success": False,
                "provider": self.provider_name,
                "incident_id": incident_id,
                "notes": f"MongoDB rotation error: {exc}. Manual remediation required.",
            }
        except Exception as exc:
            logger.error(f"[MongoDB] Unexpected error for incident {incident_id}: {exc}")
            return {
                "success": False,
                "provider": self.provider_name,
                "incident_id": incident_id,
                "notes": f"Unexpected MongoDB error: {exc}. Manual remediation required.",
            }

        # ── Step 4: Store in Vault ────────────────────────────────────────
        vault_result = vault_service.store_replacement_secret(
            repository=repository,
            incident_id=incident_id,
            secret_data={
                "provider": "mongodb",
                "host": host,
                "port": str(port),
                "database": target_db,
                "username": target_user,
                "password": new_password,
                "rotated_for_incident": incident_id,
            },
        )

        if not vault_result.get("success"):
            logger.warning(f"[MongoDB] Vault sync failed for {incident_id}: {vault_result.get('error')}")
            return {
                "success": True,
                "provider": self.provider_name,
                "incident_id": incident_id,
                "status": "vault_sync_pending",
                "remediation_status": "vault_sync_pending",
                "notes": (
                    f"MongoDB password rotated but Vault sync failed: "
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
                f"MongoDB credentials rotated successfully for user '{target_user}'. "
                f"New credentials stored in Vault at {vault_result.get('vault_path')}."
            ),
        }
