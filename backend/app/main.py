import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from app.database.base import Base
from app.database.session import engine
import app.models.incident  # noqa: F401 – ensures models are registered with Base
from app.routes.webhook import router as webhook_router
from app.routes.incidents import router as incidents_router
from app.routes.auth import router as auth_router
from app.middleware.rate_limit import RateLimitMiddleware

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure database tables exist on startup
    Base.metadata.create_all(bind=engine)
    logger.info("[Startup] Database tables created/verified.")
    yield
    logger.info("[Shutdown] Application shutting down.")


app = FastAPI(
    title="GitOps Secret Shield",
    description="Automated Secret Detection, Audit Logging and Credential Protection",
    version="2.0.0",
    lifespan=lifespan,
)

# ── Rate Limiting Middleware (Phase 2) ────────────────────────────────────────
app.add_middleware(RateLimitMiddleware)

# ── CORS (Phase 2: restricted origins in production) ─────────────────────────
_allowed_origins = os.getenv(
    "CORS_ALLOWED_ORIGINS",
    "http://localhost:5173,http://localhost:3000,http://localhost:8000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Hub-Signature-256",
                   "X-GitHub-Event", "X-GitHub-Delivery"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(auth_router, prefix="/api/v1")           # Phase 2: auth
app.include_router(webhook_router, prefix="/webhooks", tags=["GitHub Webhooks"])
app.include_router(incidents_router, prefix="/api/v1", tags=["Security Incidents"])


@app.get("/")
def home(request: Request):
    """
    Root endpoint:
    - Browser (Accept: text/html) → redirect to dashboard.
    - API client → service metadata JSON.
    """
    accept_header = request.headers.get("accept", "")
    if "text/html" in accept_header:
        return RedirectResponse(url="/dashboard/")
    return {
        "project": "GitOps Secret Shield",
        "version": "2.0.0",
        "message": "Backend is running successfully!",
        "endpoints": {
            "dashboard": "/dashboard/",
            "auth":      "/api/v1/auth/token",
            "webhooks":  "/webhooks/github",
            "incidents": "/api/v1/incidents",
            "stats":     "/api/v1/incidents/stats",
            "docs":      "/docs",
        },
    }


@app.get("/health")
def health():
    return {"status": "healthy", "version": "2.0.0"}


# ── Static Frontend Dashboard ─────────────────────────────────────────────────
frontend_dist = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")
)
if os.path.exists(frontend_dist):
    @app.get("/dashboard")
    def dashboard_redirect():
        return RedirectResponse(url="/dashboard/")

    app.mount("/dashboard", StaticFiles(directory=frontend_dist, html=True), name="dashboard")

    assets_dir = os.path.join(frontend_dist, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)
