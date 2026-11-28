import re
import math
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from app.services.risk_scoring_service import risk_scoring_service

logger = logging.getLogger(__name__)

# Enterprise-grade Secret & Credential Detection Patterns
SECRET_PATTERNS = {
    "AWS Access Key": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "GitHub Personal Access Token": r"ghp_[0-9a-zA-Z]{36}",
    "GitHub Fine-grained PAT": r"github_pat_[0-9a-zA-Z_]{82}",
    "Slack API Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Stripe Secret Key": r"(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}",
    "OpenAI API Key": r"sk-(?:proj-)?[0-9a-zA-Z\-_]{20,}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Database Credentials URI": r"(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis):\/\/[a-zA-Z0-9_\-\.]+:[^@\s]+@[a-zA-Z0-9_\-\.]+",
    "RSA / SSH Private Key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "JSON Web Token (JWT)": r"ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Exposed Password / Secret Key Assignment": r"(?i)(?:api_key|apikey|secret_key|app_secret|password|passwd|db_password|access_token)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
}


@dataclass
class DetectionRulesConfig:
    """Configurable rules for intelligent entropy and context-aware detection."""
    enable_entropy_detection: bool = True
    enable_context_detection: bool = True
    entropy_threshold: float = 4.0
    min_entropy_token_length: int = 20
    context_entropy_threshold: float = 3.5
    min_context_token_length: int = 12
    context_keywords: tuple = (
        "secret", "token", "api_key", "apikey", "password", "passwd",
        "auth_token", "client_secret", "private_key", "credential",
        "access_key", "signing_key", "encryption_key", "bearer", "dsn",
    )
    false_positive_placeholders: tuple = (
        "changeme", "change_me", "your_secret", "your-secret", "example",
        "placeholder", "dummy", "not_real", "not-real", "test_only",
        "replace_with", "insert_here", "xxxxxxxx", "00000000", "11111111",
    )


_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_SHA_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
_CONTEXT_ASSIGN_RE = re.compile(
    r"(?i)\b([a-z0-9_]*(?:secret|token|key|password|passwd|auth|credential|dsn)[a-z0-9_]*)\s*[:=]\s*['\"]([A-Za-z0-9+/=_\-!@#$%^&*]{12,})['\"]"
)
_HIGH_ENTROPY_TOKEN_RE = re.compile(r"\b([A-Za-z0-9+/=_\-]{20,})\b")


class ScannerService:
    """Service to handle intelligent automated secret scanning."""

    config = DetectionRulesConfig()

    @staticmethod
    def mask_secret(secret: str) -> str:
        """Mask secrets so sensitive values are not logged in plain text."""
        if len(secret) <= 8:
            return "********"
        return f"{secret[:4]}...{secret[-4:]}"

    @staticmethod
    def compute_fingerprint(secret: str) -> str:
        """Compute a deterministic SHA-256 fingerprint without storing raw secret."""
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy (bits per character) of a string."""
        if not data:
            return 0.0
        length = len(data)
        freq: Dict[str, int] = {}
        for ch in data:
            freq[ch] = freq.get(ch, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def is_likely_false_positive(cls, candidate: str, line: str = "") -> bool:
        """Filter out common benign high-entropy or placeholder strings."""
        lower = candidate.lower()
        if any(ph in lower for ph in cls.config.false_positive_placeholders):
            return True
        if _UUID_RE.match(candidate):
            return True
        if _HEX_SHA_RE.match(candidate) and "secret" not in line.lower() and "key" not in line.lower() and "token" not in line.lower():
            return True
        # Ignore common import/URL/repo paths without embedded credentials
        if candidate.startswith("http") and "@" not in candidate:
            return True
        if "/" in candidate and "://" not in candidate:
            if candidate.count("/") >= 2 or re.match(r"^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$", candidate):
                return True
        # Require at least 2 character classes for generic entropy tokens
        classes = sum([
            any(c.islower() for c in candidate),
            any(c.isupper() for c in candidate),
            any(c.isdigit() for c in candidate),
        ])
        if classes < 2:
            return True
        return False

    @classmethod
    def should_ignore_file(cls, file_path: str) -> bool:
        """
        Do not exclude source, test, documentation, or example files
        from secret scanning.
        """
        return False

    @classmethod
    def scan_text(
        cls,
        content: str,
        file_path: str = "commit_data",
        rules_config: Optional[DetectionRulesConfig] = None,
    ) -> List[Dict[str, Any]]:
        """
        Scans arbitrary text or code changes for exposed credentials using:
        1. Regex pattern matching
        2. Context-aware key/value inspection
        3. Shannon entropy detection
        """
        if cls.should_ignore_file(file_path):
            return []

        cfg = rules_config or cls.config
        findings: List[Dict[str, Any]] = []
        seen_on_line = set()
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            # 1. Regex pattern detections
            for detector_name, pattern in SECRET_PATTERNS.items():
                for match in re.finditer(pattern, line):
                    if (
                        detector_name == "Exposed Password / Secret Key Assignment"
                        and match.lastindex
                        and cls.is_likely_false_positive(match.group(1), line)
                    ):
                        continue
                    raw_secret = match.group(0)
                    fp = cls.compute_fingerprint(raw_secret)
                    seen_on_line.add((line_idx, fp))
                    entropy = cls.calculate_shannon_entropy(raw_secret)
                    risk = risk_scoring_service.evaluate_finding(
                        detector_name=detector_name,
                        file_path=file_path,
                        entropy=entropy,
                    )
                    findings.append({
                        "detector_name": detector_name,
                        "raw_secret_masked": cls.mask_secret(raw_secret),
                        "secret_fingerprint": fp,
                        "secret_category": risk["secret_category"],
                        "risk_score": risk["risk_score"],
                        "risk_factors": risk["risk_factors"],
                        "file_path": file_path,
                        "line_number": line_idx,
                        "severity": risk["severity"],
                        "status": "leaked",
                        "entropy": round(entropy, 2),
                    })

            # 2. Context-aware assignment detections (not already caught by regex)
            if cfg.enable_context_detection:
                for match in _CONTEXT_ASSIGN_RE.finditer(line):
                    val = match.group(2)
                    if len(val) < cfg.min_context_token_length:
                        continue
                    if cls.is_likely_false_positive(val, line):
                        continue
                    fp = cls.compute_fingerprint(val)
                    # Skip if exact same assignment or value already captured on this line
                    full_fp = cls.compute_fingerprint(match.group(0))
                    if (line_idx, fp) in seen_on_line or (line_idx, full_fp) in seen_on_line:
                        continue
                    entropy = cls.calculate_shannon_entropy(val)
                    if entropy >= cfg.context_entropy_threshold:
                        seen_on_line.add((line_idx, fp))
                        risk = risk_scoring_service.evaluate_finding(
                            detector_name="Context-Aware Secret",
                            file_path=file_path,
                            entropy=entropy,
                        )
                        findings.append({
                            "detector_name": "Context-Aware Secret",
                            "raw_secret_masked": cls.mask_secret(val),
                            "secret_fingerprint": fp,
                            "secret_category": risk["secret_category"],
                            "risk_score": risk["risk_score"],
                            "risk_factors": risk["risk_factors"],
                            "file_path": file_path,
                            "line_number": line_idx,
                            "severity": risk["severity"],
                            "status": "leaked",
                            "entropy": round(entropy, 2),
                        })

            # 3. Standalone high-entropy string detection
            if cfg.enable_entropy_detection:
                for match in _HIGH_ENTROPY_TOKEN_RE.finditer(line):
                    token = match.group(1)
                    if len(token) < cfg.min_entropy_token_length:
                        continue
                    if cls.is_likely_false_positive(token, line):
                        continue
                    fp = cls.compute_fingerprint(token)
                    if (line_idx, fp) in seen_on_line:
                        continue
                    # Avoid duplicating when regex matched a larger surrounding string containing token
                    if any(fp == existing["secret_fingerprint"] and existing["line_number"] == line_idx for existing in findings):
                        continue
                    # Check if token is a substring of a regex match on the same line
                    if any(
                        f["line_number"] == line_idx and f["detector_name"] in SECRET_PATTERNS
                        and token[:4] in f["raw_secret_masked"]
                        for f in findings
                    ):
                        continue
                    entropy = cls.calculate_shannon_entropy(token)
                    if entropy >= cfg.entropy_threshold:
                        seen_on_line.add((line_idx, fp))
                        risk = risk_scoring_service.evaluate_finding(
                            detector_name="High Entropy Secret",
                            file_path=file_path,
                            entropy=entropy,
                        )
                        findings.append({
                            "detector_name": "High Entropy Secret",
                            "raw_secret_masked": cls.mask_secret(token),
                            "secret_fingerprint": fp,
                            "secret_category": risk["secret_category"],
                            "risk_score": risk["risk_score"],
                            "risk_factors": risk["risk_factors"],
                            "file_path": file_path,
                            "line_number": line_idx,
                            "severity": risk["severity"],
                            "status": "leaked",
                            "entropy": round(entropy, 2),
                        })

        return findings

    @classmethod
    def scan_commit_payload(cls, commits: list) -> List[Dict[str, Any]]:
        """Scans commits received from a GitHub Webhook."""
        all_findings = []
        for commit in commits:
            commit_sha = commit.get("id", "unknown")
            commit_msg = commit.get("message", "")

            msg_findings = cls.scan_text(commit_msg, file_path="commit_message")
            for f in msg_findings:
                f["commit_sha"] = commit_sha
                f["author"] = commit.get("author", {}).get("username", "unknown")
                all_findings.append(f)

        return all_findings
