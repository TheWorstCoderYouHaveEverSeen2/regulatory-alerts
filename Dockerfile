FROM python:3.12-slim AS base

WORKDIR /app

# Prevent .pyc files and enable unbuffered stdout/stderr for log visibility
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system deps (needed for potential psycopg2 if switching to PostgreSQL)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY alembic.ini config.py pyproject.toml ./
COPY alembic/ alembic/
COPY src/ src/
COPY scripts/ scripts/

# Install the package in editable mode so `regulatory_alerts` is importable
RUN pip install --no-cache-dir -e .

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT:-8000}/api/health/live')" || exit 1

# Run migrations, seed feeds, then start the API server
CMD ["sh", "-c", "set -e && alembic upgrade head && python scripts/init_feeds.py && exec uvicorn regulatory_alerts.api:app --host 0.0.0.0 --port 8000 --workers 4 --timeout-graceful-shutdown 30"]
