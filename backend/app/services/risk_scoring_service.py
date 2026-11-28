"""
Secret Classification & Risk Scoring Service
Phase 3 – Task 2: GitOps Secret Shield

Classifies detected secrets by credential category and computes an
explainable, configurable risk score (0-100) and severity level
(CRITICAL, HIGH, MEDIUM, LOW) based on:
  - Secret type / credential sensitivity
  - Exposure location (env/prod config vs source vs docs/tests, commit message)
  - Verification status (verified active vs unverified vs revoked)
  - Exposure history (occurrence count / repeated exposure)
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class RiskScoringConfig:
    """Configurable weights and thresholds for risk scoring."""
    # Base sensitivity score by credential category (0-60)
    category_base_scores: Dict[str, float] = field(default_factory=lambda: {
        "cloud_iam": 55.0,
        "cryptographic_key": 55.0,
        "payment_key": 55.0,
        "database_credential": 50.0,
        "vcs_token": 50.0,
        "ai_api_key": 45.0,
        "auth_token": 40.0,
        "generic_high_entropy": 35.0,
        "generic_secret": 35.0,
    })
    # Location adjustment (-10 to +20)
    prod_path_bonus: float = 20.0
    config_path_bonus: float = 15.0
    commit_msg_bonus: float = 15.0
    test_or_doc_penalty: float = -10.0
    # Verification status adjustment
    verified_active_bonus: float = 20.0
    revoked_penalty: float = -35.0
    # Exposure history adjustment (per extra occurrence, capped)
    repeat_exposure_bonus_per_hit: float = 5.0
    max_repeat_bonus: float = 15.0
    # Severity thresholds
    critical_threshold: float = 80.0
    high_threshold: float = 60.0
    medium_threshold: float = 35.0


DETECTOR_TO_CATEGORY: Dict[str, str] = {
    "AWS Access Key": "cloud_iam",
    "Google API Key": "cloud_iam",
    "RSA / SSH Private Key": "cryptographic_key",
    "Stripe Secret Key": "payment_key",
    "Database Credentials URI": "database_credential",
    "PostgreSQL": "database_credential",
    "MySQL": "database_credential",
    "Redis": "database_credential",
    "MongoDB": "database_credential",
    "GitHub Personal Access Token": "vcs_token",
    "GitHub Fine-grained PAT": "vcs_token",
    "Github": "vcs_token",
    "OpenAI API Key": "ai_api_key",
    "Slack API Token": "auth_token",
    "JSON Web Token (JWT)": "auth_token",
    "Exposed Password / Secret Key Assignment": "generic_secret",
    "High Entropy Secret": "generic_high_entropy",
    "Context-Aware Secret": "generic_secret",
}


class RiskScoringService:
    """Computes secret classification, risk score (0-100), and severity."""

    def __init__(self, config: Optional[RiskScoringConfig] = None):
        self.config = config or RiskScoringConfig()

    @staticmethod
    def classify_detector(detector_name: str) -> str:
        """Map a detector name to a standardized credential category."""
        if detector_name in DETECTOR_TO_CATEGORY:
            return DETECTOR_TO_CATEGORY[detector_name]
        lowered = detector_name.lower()
        if any(k in lowered for k in ("aws", "gcp", "azure", "cloud")):
            return "cloud_iam"
        if any(k in lowered for k in ("postgres", "mysql", "mongo", "redis", "database", "db")):
            return "database_credential"
        if any(k in lowered for k in ("github", "gitlab", "bitbucket")):
            return "vcs_token"
        if any(k in lowered for k in ("stripe", "paypal", "payment")):
            return "payment_key"
        if any(k in lowered for k in ("rsa", "ssh", "pgp", "private key")):
            return "cryptographic_key"
        if any(k in lowered for k in ("jwt", "oauth", "bearer", "slack", "token")):
            return "auth_token"
        if "entropy" in lowered:
            return "generic_high_entropy"
        return "generic_secret"

    def _score_location(self, file_path: str) -> Tuple[float, str]:
        lower = (file_path or "").lower()
        if lower == "commit_message":
            return self.config.commit_msg_bonus, "exposed_in_commit_message"
        if any(k in lower for k in ("prod", "production", ".env", "secrets", "k8s", "helm", "terraform")):
            return self.config.prod_path_bonus, "production_or_env_file"
        if any(k in lower for k in ("config", "settings", "docker-compose", ".yml", ".yaml", ".json")):
            return self.config.config_path_bonus, "configuration_file"
        if any(k in lower for k in ("test", "spec", "mock", "example", "sample", "readme", "docs", ".md")):
            return self.config.test_or_doc_penalty, "test_or_documentation_context"
        return 10.0, "source_code_file"

    def score_to_severity(self, score: float) -> str:
        if score >= self.config.critical_threshold:
            return "CRITICAL"
        if score >= self.config.high_threshold:
            return "HIGH"
        if score >= self.config.medium_threshold:
            return "MEDIUM"
        return "LOW"

    def evaluate_finding(
        self,
        detector_name: str,
        file_path: str = "commit_data",
        verification_status: str = "unverified",  # unverified | active | revoked
        occurrence_count: int = 1,
        entropy: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate a finding and return category, risk_score, severity, and explainable risk_factors.
        Clearly separates verified facts (verification_status) from estimated risk.
        """
        category = self.classify_detector(detector_name)
        base_score = self.config.category_base_scores.get(category, 35.0)
        loc_adj, loc_reason = self._score_location(file_path)

        ver_adj = 0.0
        if verification_status == "active":
            ver_adj = self.config.verified_active_bonus
        elif verification_status == "revoked":
            ver_adj = self.config.revoked_penalty

        extra_hits = max(0, (occurrence_count or 1) - 1)
        history_adj = min(
            extra_hits * self.config.repeat_exposure_bonus_per_hit,
            self.config.max_repeat_bonus,
        )

        raw_score = base_score + loc_adj + ver_adj + history_adj
        if entropy is not None and entropy >= 4.5:
            raw_score += 5.0

        final_score = round(max(0.0, min(100.0, raw_score)), 1)
        severity = self.score_to_severity(final_score)

        factors = {
            "category": category,
            "base_sensitivity_score": base_score,
            "location_factor": loc_reason,
            "location_adjustment": loc_adj,
            "verification_fact": verification_status,
            "verification_adjustment": ver_adj,
            "occurrence_count": occurrence_count,
            "history_adjustment": history_adj,
            "entropy": round(entropy, 2) if entropy is not None else None,
            "risk_assessment_type": "verified" if verification_status in ("active", "revoked") else "estimated",
        }

        return {
            "secret_category": category,
            "risk_score": final_score,
            "severity": severity,
            "risk_factors": json.dumps(factors),
            "risk_factors_dict": factors,
        }


risk_scoring_service = RiskScoringService()
