import re
import logging
from typing import List, Dict, Any

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


class ScannerService:
    """Service to handle automated secret scanning."""

    @staticmethod
    def mask_secret(secret: str) -> str:
        """Mask secrets so sensitive values are not logged in plain text."""
        if len(secret) <= 8:
            return "********"
        return f"{secret[:4]}...{secret[-4:]}"

    @classmethod
    def should_ignore_file(cls, file_path: str) -> bool:
        """
        Do not exclude source, test, documentation, or example files
        from secret scanning.
        Binary and generated files should be filtered before scan_text()
        is called.
        """
        return False

    @classmethod
    def scan_text(cls, content: str, file_path: str = "commit_data") -> List[Dict[str, Any]]:
        """Scans arbitrary text or code changes for exposed credentials."""
        if cls.should_ignore_file(file_path):
            return []

        findings = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            for detector_name, pattern in SECRET_PATTERNS.items():
                matches = re.finditer(pattern, line)
                for match in matches:
                    raw_secret = match.group(0)
                    findings.append({
                        "detector_name": detector_name,
                        "raw_secret_masked": cls.mask_secret(raw_secret),
                        "file_path": file_path,
                        "line_number": line_idx,
                        "severity": "CRITICAL",
                        "status": "leaked",
                    })

        return findings

    @classmethod
    def scan_commit_payload(cls, commits: list) -> List[Dict[str, Any]]:
        """Scans commits received from a GitHub Webhook."""
        all_findings = []
        for commit in commits:
            commit_sha = commit.get("id", "unknown")
            commit_msg = commit.get("message", "")
            
            # Scan commit message for accidentally pasted tokens
            msg_findings = cls.scan_text(commit_msg, file_path="commit_message")
            for f in msg_findings:
                f["commit_sha"] = commit_sha
                f["author"] = commit.get("author", {}).get("username", "unknown")
                all_findings.append(f)

        return all_findings
