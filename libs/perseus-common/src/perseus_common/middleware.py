"""Pure-ASGI middleware: request context/metrics, security headers and body limits."""

from __future__ import annotations

import re
import time
import uuid

import structlog
from prometheus_client import Counter, Histogram
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from perseus_common.logging import get_logger

log = get_logger("perseus.access")

REQUEST_COUNT = Counter(
    "http_requests_total", "HTTP requests", ["service", "method", "route", "status"]
)
REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds", "HTTP request latency", ["service", "method", "route"]
)

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9\-]{8,64}$")
_QUIET_PATHS = ("/health/", "/metrics")


class RequestContextMiddleware:
    """Assigns a request id, emits one structured access-log line and records metrics.

    The request id is only accepted from upstream when it is well-formed, preventing
    log injection through a client-controlled header.
    """

    def __init__(self, app: ASGIApp, service_name: str) -> None:
        self.app = app
        self.service_name = service_name

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = dict(scope["headers"]).get(b"x-request-id", b"").decode("latin-1")
        request_id = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        status_code = 500
        start = time.perf_counter()

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode()))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration = time.perf_counter() - start
            route = scope.get("route")
            route_path = getattr(route, "path", "unmatched")
            method = scope["method"]
            REQUEST_COUNT.labels(self.service_name, method, route_path, str(status_code)).inc()
            REQUEST_LATENCY.labels(self.service_name, method, route_path).observe(duration)
            path = scope["path"]
            if not path.startswith(_QUIET_PATHS):
                client = scope.get("client")
                log.info(
                    "http_request",
                    method=method,
                    route=route_path,
                    status=status_code,
                    duration_ms=round(duration * 1000, 2),
                    client_ip=client[0] if client else None,
                )
            structlog.contextvars.clear_contextvars()


class SecurityHeadersMiddleware:
    """Adds conservative security headers suitable for a JSON API."""

    API_HEADERS: tuple[tuple[bytes, bytes], ...] = (
        (b"x-content-type-options", b"nosniff"),
        (b"x-frame-options", b"DENY"),
        (b"referrer-policy", b"no-referrer"),
        (b"cross-origin-opener-policy", b"same-origin"),
        (b"cross-origin-resource-policy", b"same-origin"),
        (b"permissions-policy", b"geolocation=(), camera=(), microphone=(), payment=()"),
        (b"cache-control", b"no-store"),
        (b"pragma", b"no-cache"),
    )
    CSP = (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'")
    HSTS = (b"strict-transport-security", b"max-age=63072000; includeSubDomains")

    def __init__(self, app: ASGIApp, *, docs_enabled: bool, hsts: bool) -> None:
        self.app = app
        self.docs_enabled = docs_enabled
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        # Swagger UI needs inline scripts; it is only ever served outside production.
        is_docs = self.docs_enabled and scope["path"] in ("/docs", "/openapi.json")

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                extra = list(self.API_HEADERS)
                if not is_docs:
                    extra.append(self.CSP)
                if self.hsts:
                    extra.append(self.HSTS)
                headers.extend(h for h in extra if h[0] not in present)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


class _BodyTooLargeError(Exception):
    pass


class BodySizeLimitMiddleware:
    """Rejects request bodies above ``max_bytes`` (declared or streamed) with 413."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None:
            try:
                too_large = int(declared) > self.max_bytes
            except ValueError:
                too_large = True
            if too_large:
                await self._reject(send)
                return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLargeError
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLargeError:
            if not response_started:
                await self._reject(send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = (
            b'{"type":"about:blank","title":"Payload Too Large","status":413,'
            b'"code":"payload_too_large","detail":"Request body exceeds the allowed size."}'
        )
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/problem+json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
