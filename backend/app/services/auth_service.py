"""
JWT Authentication & Role-Based Authorization
Phase 2: API Security for GitOps Secret Shield

Roles:
  - admin    : Full access (rotation, vault, incident management)
  - developer: Read-only access to incidents and stats

Token endpoint:  POST /api/v1/auth/token
Protected with:  Depends(require_admin) or Depends(require_developer)
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CHANGE_ME_IN_PRODUCTION_JWT_SECRET")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# ── Password Hashing ──────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── OAuth2 Bearer token scheme ────────────────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


# ── In-memory user store (dev/demo only) ─────────────────────────────────────
# In production: replace with database-backed user store.
DEMO_USERS: dict = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash(os.getenv("ADMIN_PASSWORD", "AdminSecret123!")),
        "role": "admin",
        "disabled": False,
    },
    "developer": {
        "username": "developer",
        "hashed_password": pwd_context.hash(os.getenv("DEV_PASSWORD", "DevPassword456!")),
        "role": "developer",
        "disabled": False,
    },
}


# ── Schemas ───────────────────────────────────────────────────────────────────
class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    role: str


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


class UserInDB(BaseModel):
    username: str
    role: str
    disabled: bool


# ── Helpers ───────────────────────────────────────────────────────────────────

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_user(username: str) -> Optional[UserInDB]:
    record = DEMO_USERS.get(username)
    if record:
        return UserInDB(**{k: v for k, v in record.items() if k != "hashed_password"})
    return None


def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    record = DEMO_USERS.get(username)
    if not record:
        return None
    if not verify_password(password, record["hashed_password"]):
        return None
    return UserInDB(**{k: v for k, v in record.items() if k != "hashed_password"})


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


# ── FastAPI Dependencies ──────────────────────────────────────────────────────

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub", "")
        role: str = payload.get("role", "")
        if not username:
            raise credentials_exception
        token_data = TokenData(username=username, role=role)
    except JWTError:
        raise credentials_exception

    user = get_user(token_data.username)
    if not user or user.disabled:
        raise credentials_exception
    return user


async def require_admin(current_user: UserInDB = Depends(get_current_user)) -> UserInDB:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required for this operation.",
        )
    return current_user


async def require_developer(current_user: UserInDB = Depends(get_current_user)) -> UserInDB:
    if current_user.role not in ("admin", "developer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Developer or Admin role required.",
        )
    return current_user


# ── Login endpoint handler (imported by auth_router) ─────────────────────────

async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        # Use timing-safe constant response (passlib absorbs timing via hash verify above)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=expire,
    )
    logger.info(f"[Auth] Token issued for user '{user.username}' (role={user.role})")
    return Token(
        access_token=token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        role=user.role,
    )
