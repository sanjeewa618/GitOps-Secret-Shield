import os
import hmac
import hashlib
import logging
from typing import Optional, Dict, Any, List
import httpx
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

GITHUB_API_BASE_URL = "https://api.github.com"


class GitHubService:
    """Service to handle GitHub Webhook verification and GitHub REST API communication."""

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

    @classmethod
    def _get_headers(cls) -> Dict[str, str]:
        token = os.getenv("GITHUB_TOKEN", "")
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitOps-Secret-Shield",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    @classmethod
    async def get_commit_details(cls, repo_full_name: str, commit_sha: str) -> Optional[Dict[str, Any]]:
        """Fetch detailed commit information including modified files and git diff patches."""
        url = f"{GITHUB_API_BASE_URL}/repos/{repo_full_name}/commits/{commit_sha}"
        headers = cls._get_headers()

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(url, headers=headers)
                if response.status_code == 200:
                    return response.json()
                logger.warning(f"Failed to fetch commit {commit_sha} from {repo_full_name}: HTTP {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error fetching commit details from GitHub API: {str(e)}")
            return None

    @classmethod
    async def get_commit_diff(cls, repo_full_name: str, commit_sha: str) -> Optional[str]:
        """Fetch raw unified git diff for a commit."""
        url = f"{GITHUB_API_BASE_URL}/repos/{repo_full_name}/commits/{commit_sha}"
        headers = cls._get_headers()
        headers["Accept"] = "application/vnd.github.v3.diff"

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(url, headers=headers)
                if response.status_code == 200:
                    return response.text
                return None
        except Exception as e:
            logger.error(f"Error fetching commit diff: {str(e)}")
            return None

    @classmethod
    async def get_raw_file_content(cls, repo_full_name: str, file_path: str, ref: str) -> Optional[str]:
        """Fetch the raw text content of a file at a specific commit or branch."""
        url = f"{GITHUB_API_BASE_URL}/repos/{repo_full_name}/contents/{file_path}?ref={ref}"
        headers = cls._get_headers()
        headers["Accept"] = "application/vnd.github.v3.raw"

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(url, headers=headers)
                if response.status_code == 200:
                    return response.text
                return None
        except Exception as e:
            logger.error(f"Error fetching raw file content: {str(e)}")
            return None

    @classmethod
    async def create_commit_comment(cls, repo_full_name: str, commit_sha: str, comment: str) -> bool:
        """Post a security warning comment directly on a commit on GitHub."""
        url = f"{GITHUB_API_BASE_URL}/repos/{repo_full_name}/commits/{commit_sha}/comments"
        headers = cls._get_headers()
        payload = {"body": comment}

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(url, headers=headers, json=payload)
                if response.status_code == 201:
                    logger.info(f"Successfully posted security alert comment to {commit_sha}")
                    return True
                logger.warning(f"Could not post comment (HTTP {response.status_code}): {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error posting commit comment: {str(e)}")
            return False
