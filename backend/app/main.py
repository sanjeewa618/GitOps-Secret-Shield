from fastapi import FastAPI, Response
from app.routes.webhook import router as webhook_router

app = FastAPI(
    title="GitOps Secret Shield",
    description="Automated Secret Detection and Credential Protection",
    version="1.0.0"
)

app.include_router(
    webhook_router,
    prefix="/webhooks",
    tags=["GitHub Webhooks"]
)


@app.get("/")
def home():
    return {
        "project": "GitOps Secret Shield",
        "message": "Backend is running successfully!"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# Browser favicon handler (prevents 404 in logs)
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)
