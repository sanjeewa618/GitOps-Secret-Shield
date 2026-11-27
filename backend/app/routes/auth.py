"""
Auth Routes – Phase 2
POST /api/v1/auth/token  → returns JWT access token
GET  /api/v1/auth/me     → returns current user info
"""

from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm

from app.services.auth_service import (
    Token,
    UserInDB,
    get_current_user,
    login_for_access_token,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/token", response_model=Token)
async def token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Obtain a JWT access token.

    - **username**: admin or developer
    - **password**: configured password (see ADMIN_PASSWORD / DEV_PASSWORD env vars)

    Returns a Bearer token valid for ACCESS_TOKEN_EXPIRE_MINUTES minutes.
    """
    return await login_for_access_token(form_data)


@router.get("/me", response_model=dict)
async def who_am_i(current_user: UserInDB = Depends(get_current_user)):
    """Return the authenticated user's profile (no password hash returned)."""
    return {
        "username": current_user.username,
        "role": current_user.role,
        "authenticated": True,
    }
