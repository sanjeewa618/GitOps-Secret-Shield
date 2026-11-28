"""
Git History Leak Investigation Service
Phase 3 – Task 3: GitOps Secret Shield

Scans historical Git commits in a repository without logging or storing raw secrets
or raw Git diff content. Captures masked values, secure fingerprints, commit SHAs,
timestamps, and links findings to existing incidents.
"""

import logging
import os
import subprocess
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from app.models.git_history_finding import GitHistoryFinding
from app.models.incident import Incident
from app.services.scanner_service import ScannerService

logger = logging.getLogger(__name__)


class GitHistoryService:
    """Investigates previous Git commits for exposed credentials."""

    @staticmethod
    def _run_git(repo_path: str, args: List[str]) -> str:
        """Execute a read-only git command safely."""
        result = subprocess.run(
            ["git", "-C", repo_path] + args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Git command failed: {result.stderr.strip()}")
        return result.stdout

    @classmethod
    def _sanitize_commit_message(cls, message: str) -> str:
        """Mask any potential secrets in commit messages before storing."""
        if not message:
            return ""
        first_line = message.splitlines()[0][:250]
        findings = ScannerService.scan_text(first_line, file_path="commit_message")
        if findings:
            return "[REDACTED – potential secret in commit message]"
        return first_line

    @classmethod
    def scan_repository_history(
        cls,
        db: Session,
        repo_path: str,
        repository_name: str = "sanjeewa618/GitOps-Secret-Shield",
        max_commits: int = 25,
    ) -> Dict[str, Any]:
        """
        Scan historical Git commits for secrets.
        Never stores or logs raw credentials or raw diff content.
        """
        abs_path = os.path.abspath(repo_path)
        if not os.path.isdir(os.path.join(abs_path, ".git")):
            return {
                "success": False,
                "error": f"Not a valid Git repository: {abs_path}",
                "commits_scanned": 0,
                "findings_count": 0,
                "findings": [],
            }

        # Fetch commit metadata: sha|author|iso_timestamp|subject
        log_output = cls._run_git(
            abs_path,
            ["log", f"-n{max_commits}", "--format=%H|%an|%aI|%s"],
        )

        commits = []
        for line in log_output.splitlines():
            parts = line.split("|", 3)
            if len(parts) == 4:
                commits.append({
                    "sha": parts[0].strip(),
                    "author": parts[1].strip(),
                    "timestamp": parts[2].strip(),
                    "message": parts[3].strip(),
                })

        stored_findings: List[Dict[str, Any]] = []
        repeated_fingerprints: Dict[str, int] = {}

        for c in commits:
            sha = c["sha"]
            safe_msg = cls._sanitize_commit_message(c["message"])
            try:
                committed_at = datetime.fromisoformat(c["timestamp"])
            except Exception:
                committed_at = datetime.now(timezone.utc)

            # Inspect added lines in this commit without logging diff
            try:
                diff_text = cls._run_git(
                    abs_path,
                    ["show", "--unified=0", "--no-color", "--format=", sha],
                )
            except Exception as exc:
                logger.warning(f"[GitHistory] Skipping commit {sha[:8]}: {exc}")
                continue

            current_file = "unknown"
            current_line_num = 1

            for raw_line in diff_text.splitlines():
                if raw_line.startswith("+++ b/"):
                    current_file = raw_line[6:].strip()
                    continue
                if raw_line.startswith("@@"):
                    # Parse +start line number from hunk header
                    try:
                        plus_part = [p for p in raw_line.split() if p.startswith("+")][0]
                        current_line_num = int(plus_part[1:].split(",")[0])
                    except Exception:
                        current_line_num = 1
                    continue
                if raw_line.startswith("+") and not raw_line.startswith("+++"):
                    added_content = raw_line[1:]
                    line_findings = ScannerService.scan_text(added_content, file_path=current_file)
                    for f in line_findings:
                        fp = f["secret_fingerprint"]
                        repeated_fingerprints[fp] = repeated_fingerprints.get(fp, 0) + 1

                        # Link to existing incident if one matches fingerprint or commit
                        linked_inc = db.scalars(
                            select(Incident).where(
                                (Incident.secret_fingerprint == fp) | (Incident.commit_sha == sha)
                            )
                        ).first()

                        existing = db.scalars(
                            select(GitHistoryFinding).where(
                                GitHistoryFinding.repository == repository_name,
                                GitHistoryFinding.commit_sha == sha,
                                GitHistoryFinding.detector_name == f["detector_name"],
                                GitHistoryFinding.file_path == current_file,
                                GitHistoryFinding.line_number == current_line_num,
                            )
                        ).first()

                        if not existing:
                            record = GitHistoryFinding(
                                repository=repository_name,
                                commit_sha=sha,
                                commit_message=safe_msg,
                                author=c["author"],
                                file_path=current_file,
                                line_number=current_line_num,
                                detector_name=f["detector_name"],
                                secret_masked=f["raw_secret_masked"],
                                secret_fingerprint=fp,
                                severity=f["severity"],
                                risk_score=f["risk_score"],
                                committed_at=committed_at,
                                linked_incident_id=linked_inc.incident_id if linked_inc else None,
                            )
                            db.add(record)
                            db.commit()
                            db.refresh(record)
                        else:
                            record = existing

                        stored_findings.append({
                            "id": record.id,
                            "repository": record.repository,
                            "commit_sha": record.commit_sha,
                            "commit_message": record.commit_message,
                            "author": record.author,
                            "file_path": record.file_path,
                            "line_number": record.line_number,
                            "detector_name": record.detector_name,
                            "secret_masked": record.secret_masked,
                            "secret_fingerprint": record.secret_fingerprint,
                            "severity": record.severity,
                            "risk_score": record.risk_score,
                            "committed_at": record.committed_at.isoformat() if record.committed_at else None,
                            "linked_incident_id": record.linked_incident_id,
                            "remediation_note": record.remediation_note,
                        })
                    current_line_num += 1

        logger.info(
            f"[GitHistory] Scanned {len(commits)} commits in {repository_name}; "
            f"found {len(stored_findings)} historical secret exposures."
        )

        return {
            "success": True,
            "repository": repository_name,
            "commits_scanned": len(commits),
            "findings_count": len(stored_findings),
            "repeated_exposures": {k: v for k, v in repeated_fingerprints.items() if v > 1},
            "findings": stored_findings,
        }

    @staticmethod
    def list_findings(
        db: Session,
        repository: Optional[str] = None,
        limit: int = 100,
    ) -> List[GitHistoryFinding]:
        query = select(GitHistoryFinding)
        if repository:
            query = query.where(GitHistoryFinding.repository == repository)
        return list(
            db.scalars(query.order_by(desc(GitHistoryFinding.committed_at)).limit(limit)).all()
        )
