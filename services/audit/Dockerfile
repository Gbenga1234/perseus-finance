# syntax=docker/dockerfile:1.7
# Perseus audit service. Build from the repository root:
#   docker build -f services/audit/Dockerfile -t perseus/audit .
ARG PYTHON_IMAGE=python:3.12-slim-bookworm

# ---------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder
COPY --from=ghcr.io/astral-sh/uv:0.7.20 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
# Only the workspace root, the shared library and this service enter the build, so
# changes to other services never invalidate this image's cache.
COPY pyproject.toml uv.lock ./
COPY libs ./libs
COPY services/audit ./services/audit
# --frozen: fail if uv.lock is out of date; --no-editable: the venv is self-contained.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --package audit-service

# ---------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="perseus-audit" \
      org.opencontainers.image.description="Tamper-evident, append-only audit trail"
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /nonexistent --shell /usr/sbin/nologin app \
    # Remove the package managers so a compromised container cannot install tooling.
    # The shell is kept on purpose (production maintenance via `docker exec ... sh`).
    # /var/lib/dpkg/status stays so image scanners (Trivy) can still inventory OS packages.
    && python -m pip uninstall --yes --root-user-action=ignore pip \
    && rm -rf /usr/bin/apt /usr/bin/apt-* /usr/bin/dpkg /usr/bin/dpkg-* \
              /usr/lib/apt /usr/lib/dpkg /etc/apt /var/cache/apt /var/lib/apt \
              /usr/local/bin/pip*
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_FACTORY=audit_service.main:build_app
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY services/audit/alembic.ini ./alembic.ini
COPY services/audit/migrations ./migrations
# Code is owned by root and not writable by the runtime user.
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2)"]
CMD ["python", "-m", "perseus_common.server"]
