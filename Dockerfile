# syntax=docker/dockerfile:1.7
# One Dockerfile for every service:  docker build --build-arg SERVICE=ledger .
ARG PYTHON_IMAGE=python:3.12-slim-bookworm

# ---------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder
COPY --from=ghcr.io/astral-sh/uv:0.7.20 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
ARG SERVICE
RUN test -n "${SERVICE}" || (echo "SERVICE build-arg is required" && exit 1)
COPY pyproject.toml uv.lock ./
COPY libs ./libs
COPY services ./services
# --frozen: fail if uv.lock is out of date; --no-editable: the venv is self-contained.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --package "${SERVICE}-service"

# ---------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime
ARG SERVICE
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /nonexistent --shell /usr/sbin/nologin app
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_FACTORY=${SERVICE}_service.main:build_app
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY services/${SERVICE}/alembic.ini ./alembic.ini
COPY services/${SERVICE}/migrations ./migrations
# Code is owned by root and not writable by the runtime user.
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2)"]
CMD ["python", "-m", "perseus_common.server"]
