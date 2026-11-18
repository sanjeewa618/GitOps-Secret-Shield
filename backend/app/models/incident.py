from typing import Optional
from pydantic import BaseModel
from datetime import datetime, timezone


class LeakedSecretIncident(BaseModel):
    id: Optional[int] = None
    repository: str
    commit_sha: str
    author: str
    detector_type: str
    secret_masked: str
    file_path: str
    line_number: Optional[int] = None
    status: str = "detected"  # detected, revoked, rotated, ignored
    created_at: datetime = datetime.now(timezone.utc)
