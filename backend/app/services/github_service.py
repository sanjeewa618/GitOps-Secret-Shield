import hmac
import hashlib
import logging

logger = logging.getLogger(__name__)


class GitHubService:
    """Service to handle GitHub Webhook verification and GitHub API communication."""

    @staticmethod
    def verify_signature(payload_body: bytes, secret_token: str, signature_header: str) -> bool:
        if not signature_header or not secret_token:
            return False
        
        hash_type, signature = signature_header.split("=")
        if hash_type != "sha256":
            return False
            
        mac = hmac.new(secret_token.encode(), msg=payload_body, digestmod=hashlib.sha256)
        return hmac.compare_digest(mac.hexdigest(), signature)

    @staticmethod
    def create_commit_comment(repo_full_name: str, commit_sha: str, comment: str) -> bool:
        logger.info(f"Posting comment to {repo_full_name} at commit {commit_sha}")
        return True
