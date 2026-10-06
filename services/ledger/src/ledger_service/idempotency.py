"""Idempotency-Key support (draft-ietf-httpapi-idempotency-key-header).

Retrying a money movement with the same key returns the original response instead of
moving money twice. The final response is stored in the same DB transaction as the
ledger postings, so "posted but response not recorded" cannot happen.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any

from fastapi.responses import JSONResponse
from perseus_common.errors import PROBLEM_JSON, ConflictError, UnprocessableError
from perseus_common.timeutil import utcnow
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ledger_service.models import IdempotencyRecord

Operation = Callable[[AsyncSession], Awaitable[tuple[int, dict[str, Any]]]]


def fingerprint(path: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps({"path": path, "body": payload}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _response(status_code: int, body: dict[str, Any], replayed: bool) -> JSONResponse:
    headers = {"Idempotent-Replayed": "true"} if replayed else None
    media_type = PROBLEM_JSON if status_code >= 400 else "application/json"
    return JSONResponse(body, status_code=status_code, headers=headers, media_type=media_type)


async def execute_idempotent(
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    principal_id: str,
    key: str,
    request_hash: str,
    stale_after_seconds: int,
    operation: Operation,
) -> JSONResponse:
    # Phase 1: claim the key in its own short transaction.
    async with sessionmaker() as session:
        record = await session.scalar(
            select(IdempotencyRecord).where(
                IdempotencyRecord.principal_id == principal_id, IdempotencyRecord.key == key
            )
        )
        if record is not None:
            if record.request_hash != request_hash:
                raise UnprocessableError(
                    "Idempotency-Key was already used with a different request.",
                    code="idempotency_key_reused",
                )
            if record.status_code is not None and record.response_body is not None:
                return _response(record.status_code, json.loads(record.response_body), True)
            if record.created_at > utcnow() - timedelta(seconds=stale_after_seconds):
                raise ConflictError(
                    "A request with this Idempotency-Key is still in progress.",
                    code="idempotency_in_progress",
                )
            record.created_at = utcnow()  # take over an abandoned attempt
        else:
            session.add(
                IdempotencyRecord(principal_id=principal_id, key=key, request_hash=request_hash)
            )
        try:
            await session.commit()
        except IntegrityError as exc:
            raise ConflictError(
                "A request with this Idempotency-Key is still in progress.",
                code="idempotency_in_progress",
            ) from exc

    # Phase 2: run the operation and persist its response atomically.
    try:
        async with sessionmaker() as session:
            status_code, body = await operation(session)
            record = await session.scalar(
                select(IdempotencyRecord).where(
                    IdempotencyRecord.principal_id == principal_id, IdempotencyRecord.key == key
                )
            )
            if record is None:  # pragma: no cover - deleted concurrently
                raise ConflictError("Idempotency record vanished.", code="idempotency_conflict")
            record.status_code = status_code
            record.response_body = json.dumps(body)
            await session.commit()
    except BaseException:
        # Nothing was committed: release the key so the client can safely retry.
        async with sessionmaker() as session:
            await session.execute(
                delete(IdempotencyRecord).where(
                    IdempotencyRecord.principal_id == principal_id,
                    IdempotencyRecord.key == key,
                    IdempotencyRecord.status_code.is_(None),
                )
            )
            await session.commit()
        raise
    return _response(status_code, body, False)
