# ---------- Stage 1: Build ----------
FROM python:3.13-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install .

# ---------- Stage 2: Runtime ----------
FROM python:3.13-slim

WORKDIR /app

# Runtime dependencies for PDF generation and git
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf2.0-0 \
        libffi8 \
        libcairo2 \
        fonts-liberation && \
    rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY app/ ./app/
COPY workers/ ./workers/
COPY report/ ./report/
COPY demo.py ./

# Copy probe YAML files (pre-copied by deploy.sh or docker-compose)
COPY probes/ ./probes/

# Non-root user
RUN useradd --create-home appuser
USER appuser

EXPOSE 8000

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
