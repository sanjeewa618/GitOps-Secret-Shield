from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone

app = FastAPI(
    title="GitOps Secret Shield API",
    description="Automated Secret Detection, Credential Rotation, and Leaked Secret Prevention",
    version="1.0.0",
)

# Enable CORS for React frontend (Vite/CRA)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {
        "project": "GitOps Secret Shield",
        "status": "operational",
        "docs_url": "/docs",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "GitOps Secret Shield Backend",
    }


# Fix browser 404 for favicon
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)
