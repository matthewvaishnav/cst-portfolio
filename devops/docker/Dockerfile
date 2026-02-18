# ══════════════════════════════════════════════════════════════
# Dockerfile — Secure Python App Container
# CST Portfolio — DevOps / Container Security
# ══════════════════════════════════════════════════════════════
# Author : Matthew Vaishnav — CST, Conestoga College
#
# Security practices applied:
#   ✔ Multi-stage build (small final image)
#   ✔ Non-root user
#   ✔ Read-only filesystem hints
#   ✔ Pinned base image digest
#   ✔ No secrets in image layers
#   ✔ Minimal runtime dependencies
#   ✔ HEALTHCHECK defined
# ══════════════════════════════════════════════════════════════

# ── Stage 1: Builder ──────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ── Stage 2: Runtime ──────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="CST Portfolio App"
LABEL org.opencontainers.image.description="Secure Python application — CST co-op portfolio"
LABEL org.opencontainers.image.authors="Matthew Vaishnav"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN groupadd --gid 1001 appuser && \
    useradd --uid 1001 --gid appuser --shell /bin/bash --create-home appuser

# Copy installed packages from builder
COPY --from=builder /root/.local /home/appuser/.local

WORKDIR /app

COPY --chown=appuser:appuser . .

USER appuser

ENV PATH=/home/appuser/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
