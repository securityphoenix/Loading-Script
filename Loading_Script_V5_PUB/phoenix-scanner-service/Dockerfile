# Multi-stage build for Phoenix Scanner Service
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY phoenix-scanner-service/requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# ============================================================================
# API Service
# ============================================================================
FROM base as api

# Copy application code
COPY phoenix-scanner-service/ .

# Copy parent directory scripts for Phoenix importer
COPY *.py /parent/
COPY *.ini /parent/
COPY *.yaml /parent/
COPY scanner_translators /parent/scanner_translators/
COPY format_handlers /parent/format_handlers/

# Create necessary directories
RUN mkdir -p /app/uploads /app/logs /app/data

# Expose API port (can be overridden by API_PORT env var)
EXPOSE ${API_PORT:-8000}

# Health check (uses API_PORT environment variable)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD sh -c 'python -c "import urllib.request; urllib.request.urlopen(\"http://localhost:${API_PORT:-8000}/api/v1/ping\")"'

# Run API server (port from API_PORT environment variable)
CMD sh -c "uvicorn app.main:app --host ${API_HOST:-0.0.0.0} --port ${API_PORT:-8000}"

# ============================================================================
# Worker Service
# ============================================================================
FROM base as worker

# Copy application code
COPY phoenix-scanner-service/ .

# Copy parent directory scripts for Phoenix importer
COPY *.py /parent/
COPY *.ini /parent/
COPY *.yaml /parent/
COPY scanner_translators /parent/scanner_translators/
COPY format_handlers /parent/format_handlers/

# Create necessary directories
RUN mkdir -p /app/uploads /app/logs /app/data

# Run Celery worker
CMD ["celery", "-A", "app.workers.celery_app", "worker", \
     "--loglevel=info", \
     "--concurrency=2", \
     "--max-tasks-per-child=50"]

