"""Authenticated service-to-service HTTP client (OAuth2 client-credentials)."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from perseus_common.config import ServiceSettings
from perseus_common.errors import UpstreamError
from perseus_common.logging import get_logger

log = get_logger(__name__)


class ServiceTokenProvider:
    def __init__(
        self, http: httpx.AsyncClient, token_url: str, client_id: str, client_secret: str
    ) -> None:
        self._http = http
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = asyncio.Lock()

    async def get_token(self) -> str:
        if self._token and time.monotonic() < self._expires_at:
            return self._token
        async with self._lock:
            if self._token and time.monotonic() < self._expires_at:
                return self._token
            try:
                response = await self._http.post(
                    self._token_url,
                    data={"grant_type": "client_credentials"},
                    auth=(self._client_id, self._client_secret),
                    timeout=5.0,
                )
                response.raise_for_status()
                payload = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                log.error("service_token_fetch_failed", error=type(exc).__name__)
                raise UpstreamError("Authentication service unavailable") from exc
            self._token = str(payload["access_token"])
            # Refresh a minute early to avoid using a token right as it expires.
            self._expires_at = time.monotonic() + max(int(payload["expires_in"]) - 60, 10)
            return self._token

    def invalidate(self) -> None:
        self._token = None
        self._expires_at = 0.0


class ServiceClient:
    """Calls another service's ``/internal`` API with a service token.

    GETs are retried on transport errors and 5xx. POSTs are only retried when the
    connection could not be established (the request was certainly not processed).
    """

    def __init__(
        self,
        http: httpx.AsyncClient,
        base_url: str,
        tokens: ServiceTokenProvider,
        *,
        timeout: float = 5.0,
        retries: int = 2,
    ) -> None:
        self._http = http
        self._base_url = base_url.rstrip("/")
        self._tokens = tokens
        self._timeout = timeout
        self._retries = retries

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
        response = await self._request("GET", path, params=params)
        if response.status_code == 404:
            return None
        return self._json(response)

    async def post(self, path: str, json: dict[str, Any]) -> dict[str, Any]:
        response = await self._request("POST", path, json=json)
        return self._json(response)

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        url = f"{self._base_url}{path}"
        attempt = 0
        refreshed = False
        while True:
            token = await self._tokens.get_token()
            try:
                response = await self._http.request(
                    method,
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=self._timeout,
                    **kwargs,
                )
            except httpx.ConnectError as exc:
                if attempt < self._retries:
                    attempt += 1
                    await asyncio.sleep(0.2 * 2**attempt)
                    continue
                raise UpstreamError("Dependent service unavailable") from exc
            except httpx.HTTPError as exc:
                if method == "GET" and attempt < self._retries:
                    attempt += 1
                    await asyncio.sleep(0.2 * 2**attempt)
                    continue
                raise UpstreamError("Dependent service unavailable") from exc

            if response.status_code == 401 and not refreshed:
                self._tokens.invalidate()
                refreshed = True
                continue
            if response.status_code >= 500 and method == "GET" and attempt < self._retries:
                attempt += 1
                await asyncio.sleep(0.2 * 2**attempt)
                continue
            return response

    @staticmethod
    def _json(response: httpx.Response) -> dict[str, Any]:
        if response.status_code >= 400:
            log.warning(
                "upstream_error_response", url=str(response.url), status=response.status_code
            )
            raise UpstreamError("Dependent service returned an error")
        try:
            data = response.json()
        except ValueError as exc:
            raise UpstreamError("Dependent service returned an invalid response") from exc
        if not isinstance(data, dict):
            raise UpstreamError("Dependent service returned an invalid response")
        return data


def build_token_provider(
    http: httpx.AsyncClient, settings: ServiceSettings
) -> ServiceTokenProvider:
    if not settings.service_client_id or not settings.service_client_secret:
        raise RuntimeError("service_client_id and service_client_secret must be configured")
    return ServiceTokenProvider(
        http,
        settings.auth_token_url,
        settings.service_client_id,
        settings.service_client_secret.get_secret_value(),
    )
