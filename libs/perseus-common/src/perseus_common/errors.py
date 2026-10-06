"""RFC 9457 (problem+json) error responses that never leak internals."""

from __future__ import annotations

from typing import Any, cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from perseus_common.logging import get_logger

log = get_logger(__name__)

PROBLEM_JSON = "application/problem+json"


class AppError(Exception):
    status_code = 400
    title = "Bad Request"
    code = "bad_request"

    def __init__(
        self,
        detail: str | None = None,
        *,
        code: str | None = None,
        status_code: int | None = None,
        title: str | None = None,
        headers: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.detail = detail or self.title
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code
        if title:
            self.title = title
        self.headers = headers
        self.extra = extra or {}
        super().__init__(self.detail)


class UnauthorizedError(AppError):
    status_code = 401
    title = "Unauthorized"
    code = "unauthorized"

    def __init__(self, detail: str = "Authentication required", **kwargs: Any) -> None:
        kwargs.setdefault("headers", {"WWW-Authenticate": 'Bearer error="invalid_token"'})
        super().__init__(detail, **kwargs)


class ForbiddenError(AppError):
    status_code = 403
    title = "Forbidden"
    code = "forbidden"


class NotFoundError(AppError):
    status_code = 404
    title = "Not Found"
    code = "not_found"


class ConflictError(AppError):
    status_code = 409
    title = "Conflict"
    code = "conflict"


class UnprocessableError(AppError):
    status_code = 422
    title = "Unprocessable Content"
    code = "unprocessable"


class UpstreamError(AppError):
    status_code = 503
    title = "Service Unavailable"
    code = "upstream_unavailable"


def problem_body(
    request: Request, status: int, title: str, detail: str, code: str, extra: dict[str, Any] | None
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "type": "about:blank",
        "title": title,
        "status": status,
        "detail": detail,
        "code": code,
        "instance": request.url.path,
        "request_id": getattr(request.state, "request_id", None),
    }
    if extra:
        body.update(extra)
    return body


def problem_response(
    request: Request,
    status: int,
    title: str,
    detail: str,
    code: str,
    *,
    extra: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        problem_body(request, status, title, detail, code, extra),
        status_code=status,
        media_type=PROBLEM_JSON,
        headers=headers,
    )


async def _app_error(request: Request, exc: Exception) -> JSONResponse:
    exc = cast(AppError, exc)
    return problem_response(
        request,
        exc.status_code,
        exc.title,
        exc.detail,
        exc.code,
        extra=exc.extra,
        headers=exc.headers,
    )


async def _validation_error(request: Request, exc: Exception) -> JSONResponse:
    exc = cast(RequestValidationError, exc)
    # Deliberately drop "input"/"ctx": they can echo back passwords or other secrets.
    errors = [
        {"loc": list(err.get("loc", ())), "msg": err.get("msg"), "type": err.get("type")}
        for err in exc.errors()
    ]
    return problem_response(
        request,
        422,
        "Validation Failed",
        "The request is invalid.",
        "validation_error",
        extra={"errors": errors},
    )


async def _http_error(request: Request, exc: Exception) -> JSONResponse:
    exc = cast(StarletteHTTPException, exc)
    title = {404: "Not Found", 405: "Method Not Allowed"}.get(exc.status_code, "Error")
    detail = exc.detail if isinstance(exc.detail, str) else title
    return problem_response(
        request,
        exc.status_code,
        title,
        detail,
        f"http_{exc.status_code}",
        headers=getattr(exc, "headers", None),
    )


async def _unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled_exception", path=request.url.path, error_type=type(exc).__name__)
    return problem_response(
        request, 500, "Internal Server Error", "An unexpected error occurred.", "internal_error"
    )


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(Exception, _unhandled_error)
