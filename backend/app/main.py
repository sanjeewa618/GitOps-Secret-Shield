import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from app.database.base import Base
from app.database.session import engine
import app.models.incident  # Ensures models are registered with Base metadata
from app.routes.webhook import router as webhook_router
from app.routes.incidents import router as incidents_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure database tables exist on startup
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="GitOps Secret Shield",
    description="Automated Secret Detection, Audit Logging and Credential Protection",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for Security Dashboard frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(
    webhook_router,
    prefix="/webhooks",
    tags=["GitHub Webhooks"],
)

app.include_router(
    incidents_router,
    prefix="/api/v1",
    tags=["Security Incidents"],
)


@app.get("/")
def home(request: Request):
    """
    Root endpoint:
    - If accessed from a web browser (Accept: text/html), automatically redirect to the Security Dashboard.
    - If accessed via curl or API client, return service metadata and endpoint discovery JSON.
    """
    accept_header = request.headers.get("accept", "")
    if "text/html" in accept_header:
        return RedirectResponse(url="/dashboard/")

    return {
        "project": "GitOps Secret Shield",
        "message": "Backend is running successfully!",
        "endpoints": {
            "dashboard": "/dashboard/",
            "webhooks": "/webhooks/github",
            "incidents": "/api/v1/incidents",
            "stats": "/api/v1/incidents/stats",
            "docs": "/docs",
        },
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# Mount built React Frontend Dashboard if available
frontend_dist = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")
)
if os.path.exists(frontend_dist):
    @app.get("/dashboard")
    def dashboard_redirect():
        return RedirectResponse(url="/dashboard/")

    app.mount("/dashboard", StaticFiles(directory=frontend_dist, html=True), name="dashboard")

    # Fallback mount for direct root /assets requests
    assets_dir = os.path.join(frontend_dist, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")


# Browser favicon handler (prevents 404 in logs)
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)
