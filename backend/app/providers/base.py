from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class BaseRotationProvider(ABC):
    """Abstract base class for automated credential rotation providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the provider (e.g. 'PostgreSQL', 'AWS', etc.)"""
        pass

    @abstractmethod
    def can_handle(self, detector_name: str) -> bool:
        """Return True if this provider is responsible for this secret type."""
        pass

    @abstractmethod
    def rotate(
        self,
        repository: str,
        incident_id: str,
        detector_name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute credential rotation, store the new secret in Vault, and return result details.
        """
        pass
