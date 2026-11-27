# ============================================================
# GitOps Secret Shield – Backend Dockerfile
# Phase 2: Production-ready, non-root user
# ============================================================
FROM python:3.11-slim AS base

# Security: Create a non-root user
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app

# Install Python dependencies (as root)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Switch to non-root
USER 1001:1001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "2", "--no-access-log"]
