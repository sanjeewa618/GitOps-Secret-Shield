from fastapi import FastAPI, Response
from app.routes.webhook import router as webhook_router

app = FastAPI(
    title="GitOps Secret Shield",
    description="Automated Secret Detection and Credential Rotation System",
    version="1.0.0",
)


@app.get("/")
def home():
    return {
        "project": "GitOps Secret Shield",
        "message": "Backend is running successfully!",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "GitOps Secret Shield Backend",
    }


# Fix for browser 404 on favicon.ico
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


# Register modular routers
app.include_router(webhook_router, prefix="/api/v1")
