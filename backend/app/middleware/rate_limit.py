"""
API Rate Limiting Middleware
Phase 2: GitOps Secret Shield

Implements a sliding-window rate limiter per client IP.
Configuration via environment variables:
  RATE_LIMIT_REQUESTS  – max requests per window (default: 60)
  RATE_LIMIT_WINDOW_S  – window size in seconds (default: 60)
  RATE_LIMIT_AUTH_REQUESTS – stricter limit for /auth endpoints (default: 10)
"""

import time
import logging
import os
from collections import defaultdict, deque
from typing import Deque

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
RATE_LIMIT_WINDOW_S = int(os.getenv("RATE_LIMIT_WINDOW_S", "60"))
RATE_LIMIT_AUTH_REQUESTS = int(os.getenv("RATE_LIMIT_AUTH_REQUESTS", "10"))

# In-memory sliding window store: { ip: deque([timestamps]) }
_request_log: dict[str, Deque[float]] = defaultdict(deque)


def _get_client_ip(request: Request) -> str:
    """Extract client IP, respecting trusted reverse-proxy headers."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _is_auth_path(path: str) -> bool:
    return "/auth/" in path or path.endswith("/auth/token")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window rate limiter.
    Returns HTTP 429 when the client exceeds the configured request limit.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Exempt health checks and static assets
        if request.url.path in ("/health", "/favicon.ico") or request.url.path.startswith("/dashboard"):
            return await call_next(request)

        client_ip = _get_client_ip(request)
        now = time.monotonic()
        window = _request_log[client_ip]

        # Determine which limit applies
        limit = RATE_LIMIT_AUTH_REQUESTS if _is_auth_path(request.url.path) else RATE_LIMIT_REQUESTS

        # Evict timestamps outside the current window
        while window and now - window[0] > RATE_LIMIT_WINDOW_S:
            window.popleft()

        if len(window) >= limit:
            retry_after = int(RATE_LIMIT_WINDOW_S - (now - window[0])) + 1
            logger.warning(
                f"[RateLimit] {client_ip} exceeded {limit} req/{RATE_LIMIT_WINDOW_S}s "
                f"on {request.url.path}"
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please slow down.",
                    "retry_after_seconds": retry_after,
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + retry_after),
                },
            )

        window.append(now)
        response = await call_next(request)

        # Inject informational headers on successful responses
        remaining = max(0, limit - len(window))
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
