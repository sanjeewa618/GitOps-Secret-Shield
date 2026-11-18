import hmac
import hashlib
import logging

logger = logging.getLogger(__name__)


class GitHubService:
    """Service to handle GitHub Webhook verification and GitHub API communication."""

    @staticmethod
    def verify_signature(
        payload_body: bytes,
        secret_token: str,
        signature_header: str
    ) -> bool:
        """Safely verify GitHub webhook HMAC-SHA256 signature without crashing on malformed headers."""
        if not secret_token or not signature_header:
            return False

        hash_type, separator, signature = signature_header.partition("=")
        if not separator or hash_type != "sha256" or not signature:
            return False

        expected_signature = hmac.new(
            secret_token.encode("utf-8"),
            msg=payload_body,
            digestmod=hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected_signature, signature)

    @staticmethod
    def create_commit_comment(repo_full_name: str, commit_sha: str, comment: str) -> bool:
        logger.info(f"Posting comment to {repo_full_name} at commit {commit_sha}")
        return True
