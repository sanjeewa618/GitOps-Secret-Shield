import logging
from typing import Optional, Dict, Any
import httpx
from app.config.settings import settings

logger = logging.getLogger(__name__)


class VaultService:
    """Service to interact with HashiCorp Vault KV v2 secrets engine."""

    def __init__(
        self,
        vault_addr: Optional[str] = None,
        token: Optional[str] = None,
    ):
        self.vault_addr = (vault_addr or settings.VAULT_ADDR).rstrip("/")
        self.token = token or settings.VAULT_TOKEN
        self.base_url = f"{self.vault_addr}/v1"

    def _headers(self) -> Dict[str, str]:
        return {
            "X-Vault-Token": self.token,
            "Content-Type": "application/json",
        }

    def _format_vault_path(self, repository: str, incident_id: str) -> str:
        """Sanitizes repository name and builds a structured Vault KV v2 path."""
        sanitized_repo = repository.lower().replace(" ", "-").strip("/")
        return f"gitops-secret-shield/{sanitized_repo}/{incident_id}"

    def check_health(self) -> Dict[str, Any]:
        """Check if HashiCorp Vault is initialized, unsealed, and reachable."""
        url = f"{self.base_url}/sys/health"
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(url)
                # Vault returns 200 (healthy active), 429 (unsealed standby), 472 (disaster recovery), 473 (performance standby)
                if res.status_code in (200, 429):
                    data = res.json()
                    return {
                        "status": "healthy",
                        "initialized": data.get("initialized", True),
                        "sealed": data.get("sealed", False),
                        "version": data.get("version", "unknown"),
                    }
                else:
                    return {
                        "status": "unhealthy",
                        "status_code": res.status_code,
                        "details": res.text,
                    }
        except Exception as e:
            logger.warning(f"HashiCorp Vault connection failed at {url}: {e}")
            return {
                "status": "unreachable",
                "error": str(e),
                "vault_addr": self.vault_addr,
            }

    def store_replacement_secret(
        self,
        repository: str,
        incident_id: str,
        secret_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Store rotated/replacement credentials securely in HashiCorp Vault KV v2.
        Path format: secret/data/gitops-secret-shield/{repository}/{incident_id}
        """
        subpath = self._format_vault_path(repository, incident_id)
        endpoint = f"{self.base_url}/secret/data/{subpath}"
        payload = {"data": secret_data}

        try:
            with httpx.Client(timeout=10.0) as client:
                res = client.post(endpoint, headers=self._headers(), json=payload)
                if res.status_code in (200, 204):
                    res_json = res.json() if res.content else {}
                    version = (
                        res_json.get("data", {}).get("version")
                        if res_json
                        else 1
                    )
                    full_path = f"secret/data/{subpath}"
                    logger.info(f"Successfully stored credential in Vault: {full_path}")
                    return {
                        "success": True,
                        "vault_path": full_path,
                        "version": version,
                    }
                else:
                    logger.error(f"Failed to store secret in Vault: HTTP {res.status_code} - {res.text}")
                    return {
                        "success": False,
                        "error": f"Vault returned HTTP {res.status_code}: {res.text}",
                        "vault_path": f"secret/data/{subpath}",
                    }
        except Exception as e:
            logger.error(f"Error connecting to Vault at {endpoint}: {e}")
            return {
                "success": False,
                "error": str(e),
                "vault_path": f"secret/data/{subpath}",
            }

    def get_secret(
        self,
        repository: str,
        incident_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve stored credentials from HashiCorp Vault KV v2."""
        subpath = self._format_vault_path(repository, incident_id)
        endpoint = f"{self.base_url}/secret/data/{subpath}"

        try:
            with httpx.Client(timeout=10.0) as client:
                res = client.get(endpoint, headers=self._headers())
                if res.status_code == 200:
                    data = res.json().get("data", {}).get("data", {})
                    return data
                elif res.status_code == 404:
                    logger.info(f"Secret not found at Vault path: {subpath}")
                    return None
                else:
                    logger.warning(f"Error fetching from Vault: HTTP {res.status_code} - {res.text}")
                    return None
        except Exception as e:
            logger.error(f"Error reading secret from Vault at {endpoint}: {e}")
            return None

    def revoke_secret(
        self,
        repository: str,
        incident_id: str,
    ) -> bool:
        """Soft-delete secret version from HashiCorp Vault KV v2."""
        subpath = self._format_vault_path(repository, incident_id)
        endpoint = f"{self.base_url}/secret/data/{subpath}"

        try:
            with httpx.Client(timeout=10.0) as client:
                res = client.delete(endpoint, headers=self._headers())
                return res.status_code in (200, 204)
        except Exception as e:
            logger.error(f"Error revoking secret from Vault at {endpoint}: {e}")
            return False


# Singleton instance for application-wide use
vault_service = VaultService()
