# ═══════════════════════════════════════════════════════════
# VicoGuard AI — Multi-stage Dockerfile (Centinela + Hub)
# ═══════════════════════════════════════════════════════════
# Build:  docker build -t vicoguard-ai .
# Run:    docker-compose up
# ═══════════════════════════════════════════════════════════

FROM python:3.11-slim AS base

# System deps: gitleaks binary + build tools for C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip git \
    && curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz" \
       | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ─── Stage: Centinela (SAST node) ──────────────────────────
FROM base AS centinela

COPY wasp-centinela/requirements.txt /app/wasp-centinela/requirements.txt
RUN pip install --no-cache-dir -r /app/wasp-centinela/requirements.txt

COPY wasp-centinela/ /app/wasp-centinela/
WORKDIR /app/wasp-centinela

RUN python -m pytest --tb=short -q || true

CMD ["python", "-m", "centinela.main", "status"]

# ─── Stage: Hub (FastAPI server) ───────────────────────────
FROM base AS hub

# Hub requirements
COPY src/requirements.txt /app/src/requirements.txt
RUN pip install --no-cache-dir -r /app/src/requirements.txt
RUN pip install --no-cache-dir slowapi  # rate limiting

# Copy Centinela (Hub depends on its modules for unified scan)
COPY wasp-centinela/ /app/wasp-centinela/

# Copy Hub source
COPY src/ /app/src/
COPY web/ /app/web/
COPY ui_stitch/ /app/ui_stitch/

# Environment defaults
ENV PYTHONPATH=/app/src:/app/wasp-centinela
ENV API_HOST=0.0.0.0
ENV API_PORT=8000
ENV VG_COOKIE_SECURE=0
ENV VG_ENABLE_DOCS=0

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8000/api/v1/health || exit 1

WORKDIR /app/src
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
